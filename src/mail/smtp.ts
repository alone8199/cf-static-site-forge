/// 最小 SMTP 客户端（基于 Workers 的 cloudflare:sockets）。
/// 支持：隐式 TLS（465）、STARTTLS（587）、AUTH PLAIN / LOGIN。
/// 安全要点：
///   - 默认强制加密：凭据只在 TLS 连接（隐式或 STARTTLS 升级后）上发送
///   - 凭据、令牌、完整邮件内容永不写入日志或错误信息
///   - 头部字段拒绝 CR/LF，防止头注入
///   - 所有读写都有超时
import { connect, type Socket } from "cloudflare:sockets";
import { bytesToB64, randomId } from "../lib/crypto";

export interface SmtpConfig {
  host: string;
  port: number;
  /** EHLO 使用的主机名（一般为主应用域名） */
  heloName: string;
  tls: "implicit" | "starttls" | "none";
  timeoutMs: number;
  requireAuth: boolean;
  username?: string;
  password?: string;
}

export interface MailMessage {
  from: string;
  fromName: string;
  to: string;
  subject: string;
  text: string;
  /** 用于生成 Message-ID 的域名（一般为主应用域） */
  messageIdDomain: string;
}

export class SmtpError extends Error {
  /** 对外安全的描述，不含凭据或服务端原始内容 */
  constructor(public readonly step: string) {
    super(`smtp_${step}`);
    this.name = "SmtpError";
  }
}

const enc = new TextEncoder();
const dec = new TextDecoder();
const EMAIL_RE = /^[^\s@<>()[\],;:"\\]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;

function assertNoCRLF(v: string, step: string): void {
  if (/[\r\n\0]/.test(v)) throw new SmtpError(step);
}

function withTimeout<T>(p: Promise<T>, ms: number, step: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const t = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new SmtpError(`${step}_timeout`)), ms);
  });
  return Promise.race([p, t]).finally(() => clearTimeout(timer));
}

/// 行读取器：处理多行响应（250-xxx ... 250 xxx）。
class LineReader {
  private buf = "";
  private decoder = new TextDecoder();
  constructor(private reader: ReadableStreamDefaultReader<Uint8Array>, private timeoutMs: number) {}

  private async readLine(): Promise<string> {
    for (;;) {
      const idx = this.buf.indexOf("\r\n");
      if (idx >= 0) {
        const line = this.buf.slice(0, idx);
        this.buf = this.buf.slice(idx + 2);
        return line;
      }
      if (this.buf.length > 16 * 1024) throw new SmtpError("response_too_long");
      const { value, done } = await withTimeout(this.reader.read(), this.timeoutMs, "read");
      if (done || !value) throw new SmtpError("connection_closed");
      this.buf += this.decoder.decode(value, { stream: true });
    }
  }

  async response(): Promise<{ code: number; lines: string[] }> {
    const lines: string[] = [];
    for (let guard = 0; guard < 100; guard++) {
      const line = await this.readLine();
      lines.push(line);
      const m = /^(\d{3})([ -])/.exec(line);
      if (!m) throw new SmtpError("bad_response");
      if (m[2] === " ") return { code: Number(m[1]), lines };
    }
    throw new SmtpError("too_many_lines");
  }

  rebind(reader: ReadableStreamDefaultReader<Uint8Array>): void {
    this.reader = reader;
    this.buf = "";
  }
}

class Conn {
  constructor(
    public socket: Socket,
    public lines: LineReader,
    private writer: WritableStreamDefaultWriter<Uint8Array>,
    private timeoutMs: number,
  ) {}

  async send(data: string): Promise<void> {
    await withTimeout(this.writer.write(enc.encode(data)), this.timeoutMs, "write");
  }

  async command(cmd: string, expect: number[], step: string): Promise<{ code: number; lines: string[] }> {
    await this.send(cmd + "\r\n");
    const res = await this.lines.response();
    if (!expect.includes(res.code)) throw new SmtpError(step);
    return res;
  }

  rebindWriter(writer: WritableStreamDefaultWriter<Uint8Array>): void {
    this.writer = writer;
  }
}

function capabilities(lines: string[]): string[] {
  return lines.slice(1).map((l) => l.slice(4).trim().toUpperCase());
}

function encodeHeader(value: string): string {
  return `=?UTF-8?B?${bytesToB64(enc.encode(value))}?=`;
}

function buildMessage(m: MailMessage): string {
  const body = bytesToB64(enc.encode(m.text.replace(/\r?\n/g, "\r\n")));
  // Base64 正文按 76 字符折行
  const wrapped = body.match(/.{1,76}/g)?.join("\r\n") ?? "";
  const headers = [
    `From: ${encodeHeader(m.fromName)} <${m.from}>`,
    `To: <${m.to}>`,
    `Subject: ${encodeHeader(m.subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${randomId(12)}@${m.messageIdDomain}>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: base64",
  ];
  return headers.join("\r\n") + "\r\n\r\n" + wrapped + "\r\n";
}

/// 发送一封纯文本邮件。失败抛出 SmtpError（只含步骤名，不含细节）。
export async function sendSmtpMail(cfg: SmtpConfig, msg: MailMessage): Promise<void> {
  // 校验输入：防止头注入与非法地址
  assertNoCRLF(msg.from, "from");
  assertNoCRLF(msg.to, "to");
  assertNoCRLF(msg.subject, "subject");
  assertNoCRLF(msg.fromName, "from_name");
  if (!EMAIL_RE.test(msg.from) || !EMAIL_RE.test(msg.to)) throw new SmtpError("address");

  const hasCreds = !!(cfg.username && cfg.password);
  if (cfg.tls === "none" && hasCreds) throw new SmtpError("plaintext_auth_refused");
  if (cfg.requireAuth && !hasCreds) throw new SmtpError("auth_not_configured");

  const secureTransport = cfg.tls === "implicit" ? "on" : cfg.tls === "starttls" ? "starttls" : "off";
  let socket: Socket;
  try {
    socket = connect({ hostname: cfg.host, port: cfg.port }, { secureTransport, allowHalfOpen: false });
    await withTimeout(socket.opened, cfg.timeoutMs, "connect");
  } catch {
    throw new SmtpError("connect");
  }

  let conn: Conn | null = null;
  try {
    conn = new Conn(
      socket,
      new LineReader(socket.readable.getReader(), cfg.timeoutMs),
      socket.writable.getWriter(),
      cfg.timeoutMs,
    );
    const greet = await conn.lines.response();
    if (greet.code !== 220) throw new SmtpError("greeting");

    const ehloName = cfg.heloName;
    let ehlo = await conn.command(`EHLO ${ehloName}`, [250], "ehlo");

    if (cfg.tls === "starttls") {
      await conn.command("STARTTLS", [220], "starttls");
      // STARTTLS 之后原有 reader/writer 失效，必须使用 startTls() 返回的新 socket
      const secure = socket.startTls();
      conn.socket = secure;
      conn.rebindWriter(secure.writable.getWriter());
      conn.lines.rebind(secure.readable.getReader());
      ehlo = await conn.command(`EHLO ${ehloName}`, [250], "ehlo_tls");
    }

    const caps = capabilities(ehlo.lines);
    if (hasCreds) {
      if (caps.some((c) => c.startsWith("AUTH") && c.includes("PLAIN"))) {
        const token = bytesToB64(enc.encode(`\0${cfg.username}\0${cfg.password}`));
        await conn.command(`AUTH PLAIN ${token}`, [235], "auth");
      } else if (caps.some((c) => c.startsWith("AUTH") && c.includes("LOGIN"))) {
        await conn.command("AUTH LOGIN", [334], "auth");
        await conn.command(bytesToB64(enc.encode(cfg.username!)), [334], "auth");
        await conn.command(bytesToB64(enc.encode(cfg.password!)), [235], "auth");
      } else {
        throw new SmtpError("auth_unsupported");
      }
    } else if (cfg.requireAuth) {
      throw new SmtpError("auth_not_configured");
    }

    await conn.command(`MAIL FROM:<${msg.from}>`, [250], "mail_from");
    await conn.command(`RCPT TO:<${msg.to}>`, [250, 251], "rcpt_to");
    await conn.command("DATA", [354], "data");
    await conn.send(buildMessage(msg) + ".\r\n");
    const done = await conn.lines.response();
    if (done.code !== 250) throw new SmtpError("data_rejected");
    await conn.send("QUIT\r\n").catch(() => {});
  } catch (e) {
    if (e instanceof SmtpError) throw e;
    throw new SmtpError("protocol");
  } finally {
    try {
      // STARTTLS 后应关闭升级后的 socket
      await (conn?.socket ?? socket).close();
    } catch {
      /* 忽略关闭错误 */
    }
  }
}
