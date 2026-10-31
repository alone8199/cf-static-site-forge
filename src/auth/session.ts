/// 会话管理：数据库只存 session token 的 SHA-256 哈希；Cookie 为 HttpOnly + Secure + SameSite=Strict。
import type { Env } from "../env";
import { readLimits } from "../env";
import { randomToken, sha256Hex } from "../lib/crypto";
import { hashIp } from "../lib/audit";

export const SESSION_COOKIE = "__Host-sid";

export interface SessionRecord {
  userId: string;
  csrfToken: string;
  expiresAt: number;
}

export function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

export async function createSession(
  env: Env,
  userId: string,
  ip: string | null,
): Promise<{ token: string; csrfToken: string; expiresAt: number }> {
  const limits = readLimits(env);
  const token = randomToken(32);
  const csrfToken = randomToken(32);
  const createdAt = nowSec();
  const expiresAt = createdAt + limits.sessionTtlSeconds;
  const tokenHash = await sha256Hex(token);

  await env.DB.prepare(
    `INSERT INTO sessions (token_hash, user_id, csrf_token, ip_hash, created_at, expires_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
  )
    .bind(tokenHash, userId, csrfToken, await hashIp(env, ip), createdAt, expiresAt)
    .run();

  // 顺便清理过期会话（机会性清理）
  await env.DB.prepare(`DELETE FROM sessions WHERE expires_at < ?1`).bind(createdAt).run();

  return { token, csrfToken, expiresAt };
}

/// 通过 Cookie 中的 token 查找会话。过期或不存在返回 null。
export async function loadSession(env: Env, token: string): Promise<SessionRecord | null> {
  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT user_id, csrf_token, expires_at FROM sessions WHERE token_hash = ?1`,
  )
    .bind(tokenHash)
    .first<{ user_id: string; csrf_token: string; expires_at: number }>();

  if (!row) return null;
  if (row.expires_at <= nowSec()) {
    await env.DB.prepare(`DELETE FROM sessions WHERE token_hash = ?1`).bind(tokenHash).run();
    return null;
  }
  return { userId: row.user_id, csrfToken: row.csrf_token, expiresAt: row.expires_at };
}

export async function destroySession(env: Env, token: string): Promise<void> {
  const tokenHash = await sha256Hex(token);
  await env.DB.prepare(`DELETE FROM sessions WHERE token_hash = ?1`).bind(tokenHash).run();
}

/// 修改密码后吊销该用户所有会话（包括当前会话，由调用方重新签发）
export async function revokeAllSessions(env: Env, userId: string): Promise<void> {
  await env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?1`).bind(userId).run();
}

/// 构造 Set-Cookie 头。__Host- 前缀要求 Secure、Path=/、无 Domain。
export function sessionCookie(token: string, maxAgeSeconds: number): string {
  return [
    `${SESSION_COOKIE}=${token}`,
    "Path=/",
    `Max-Age=${maxAgeSeconds}`,
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
  ].join("; ");
}

export function clearSessionCookie(): string {
  return `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;
}

/// 从 Cookie 头中取出会话 token（严格解析，不接受异常格式）
export function readSessionToken(cookieHeader: string | null): string | null {
  if (!cookieHeader) return null;
  for (const part of cookieHeader.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === SESSION_COOKIE) {
      const value = rest.join("=");
      return /^[A-Za-z0-9_-]{20,128}$/.test(value) ? value : null;
    }
  }
  return null;
}
