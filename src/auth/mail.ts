/// 验证邮件发送。模式由 config/app.config.ts 的 mail.mode 决定：
///   - smtp（默认）：通过 SMTP 发送。凭据来自 SMTP_USERNAME / SMTP_PASSWORD Secret。
///   - dev：仅本地开发。令牌随接口响应返回。生产环境禁止启用。
///   - none：不发送，只能通过 BOOTSTRAP_TOKEN 完成管理员初始化。
import type { Env } from "../env";
import { getConfig } from "../config";
import { sendSmtpMail, SmtpError } from "../mail/smtp";

export interface VerificationDelivery {
  /** 仅 dev 模式返回令牌 */
  devToken?: string;
  sent: boolean;
}

export async function deliverVerification(env: Env, email: string, token: string): Promise<VerificationDelivery> {
  const cfg = getConfig();
  const mode = cfg.mail.mode;

  if (mode === "dev") {
    return { devToken: token, sent: false };
  }
  if (mode === "none") {
    return { sent: false };
  }

  const link = `${cfg.app.origin}/verify-email?token=${encodeURIComponent(token)}`;
  const text = [
    `您好，`,
    ``,
    `请点击下面的链接完成 ${cfg.app.name} 的邮箱验证（24 小时内有效）：`,
    link,
    ``,
    `如果这不是您本人的操作，请忽略此邮件。`,
  ].join("\n");

  try {
    await sendSmtpMail(
      {
        host: cfg.mail.smtp.host,
        port: cfg.mail.smtp.port,
        tls: cfg.mail.smtp.tls,
        timeoutMs: cfg.mail.smtp.timeoutMs,
        requireAuth: cfg.mail.smtp.requireAuth,
        heloName: new URL(cfg.app.origin).hostname,
        username: env.SMTP_USERNAME,
        password: env.SMTP_PASSWORD,
      },
      {
        from: cfg.mail.from,
        fromName: cfg.mail.fromName,
        to: email,
        subject: cfg.mail.subject,
        text,
        messageIdDomain: new URL(cfg.app.origin).hostname,
      },
    );
    return { sent: true };
  } catch (e) {
    // 只记录错误步骤名，不记录邮箱、令牌或服务端原始响应
    console.error("smtp_send_failed", e instanceof SmtpError ? e.step : "unknown");
    return { sent: false };
  }
}
