/// 密码哈希、令牌生成、HMAC 与常量时间比较。全部基于 WebCrypto。

const enc = new TextEncoder();

export function bytesToB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64ToBytes(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/// 生成 n 字节的密码学安全随机数
export function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

/// URL 安全的随机令牌（base64url，无填充）
export function randomToken(bytes = 32): string {
  return bytesToB64(randomBytes(bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/// 不可猜测的站点 ID：128 bit，小写十六进制
export function randomId(bytes = 16): string {
  return bytesToHex(randomBytes(bytes));
}

export async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const data = typeof input === "string" ? enc.encode(input) : input;
  const digest = await crypto.subtle.digest("SHA-256", data);
  return bytesToHex(new Uint8Array(digest));
}

/// HMAC-SHA256，用于验证码答案与 IP 哈希（密钥来自 Secret）
export async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return bytesToHex(new Uint8Array(sig));
}

/// PBKDF2-SHA256 派生密钥，每用户独立盐
export async function pbkdf2Hash(
  password: string,
  salt: Uint8Array,
  iterations: number,
): Promise<string> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    256,
  );
  return bytesToB64(new Uint8Array(bits));
}

export interface PasswordRecord {
  hash: string;
  salt: string;
  iterations: number;
}

export async function hashPassword(password: string, iterations: number): Promise<PasswordRecord> {
  const salt = randomBytes(16);
  const hash = await pbkdf2Hash(password, salt, iterations);
  return { hash, salt: bytesToB64(salt), iterations };
}

export async function verifyPassword(
  password: string,
  record: PasswordRecord,
): Promise<boolean> {
  const computed = await pbkdf2Hash(password, b64ToBytes(record.salt), record.iterations);
  return timingSafeEqual(computed, record.hash);
}

/// 常量时间字符串比较（长度不同时也不提前泄露内容）
export function timingSafeEqual(a: string, b: string): boolean {
  const ea = enc.encode(a);
  const eb = enc.encode(b);
  const len = Math.max(ea.length, eb.length);
  let diff = ea.length ^ eb.length;
  for (let i = 0; i < len; i++) {
    diff |= (ea[i] ?? 0) ^ (eb[i] ?? 0);
  }
  return diff === 0;
}
