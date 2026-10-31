/// 审计日志。写入 D1 audit_logs。
/// 只记录动作、目标、结果与 IP 哈希；绝不记录密码、验证码答案、session token、邮件 token。
import type { Env } from "../env";
import { hmacHex } from "./crypto";

export interface AuditEvent {
  actorId?: string | null;
  action: string;
  target?: string | null;
  result: "ok" | "denied" | "error";
}

/// IP 只存 HMAC 哈希（IP_HASH_SECRET）。无法从日志反推原始地址。
export async function hashIp(env: Env, ip: string | null | undefined): Promise<string | null> {
  if (!ip) return null;
  return (await hmacHex(env.IP_HASH_SECRET, ip)).slice(0, 32);
}

/// 写入审计日志。失败不阻断主流程（best-effort），但不会静默吞掉敏感信息。
export async function audit(env: Env, ip: string | null | undefined, ev: AuditEvent): Promise<void> {
  try {
    const ipHash = await hashIp(env, ip);
    await env.DB.prepare(
      `INSERT INTO audit_logs (actor_id, action, target, ip_hash, result, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
    )
      .bind(
        ev.actorId ?? null,
        ev.action.slice(0, 64),
        ev.target ? ev.target.slice(0, 128) : null,
        ipHash,
        ev.result,
        Math.floor(Date.now() / 1000),
      )
      .run();
  } catch {
    // 审计写入失败不应暴露给用户；错误详情也不记录，避免泄露内容。
  }
}
