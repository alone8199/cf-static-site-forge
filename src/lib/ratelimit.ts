/// 基于 KV 的固定窗口速率限制。
/// 注意：KV 最终一致、非原子。它能有效拦截暴力破解与脚本滥用，但不是精确计数；
/// 生产环境建议同时启用 Cloudflare Rate Limiting 规则（见 README）。
import type { Env } from "../env";
import { err } from "./errors";
import { sha256Hex } from "./crypto";

export interface RateRule {
  /** 规则名，仅用于 key 命名 */
  name: string;
  /** 窗口内允许的最大次数 */
  limit: number;
  /** 窗口长度（秒），最小 60（KV TTL 限制） */
  windowSeconds: number;
}

/// 规则集中定义，便于审计
export const RULES = {
  login: { name: "login", limit: 10, windowSeconds: 900 },
  loginAccount: { name: "login_acct", limit: 5, windowSeconds: 900 },
  register: { name: "register", limit: 5, windowSeconds: 3600 },
  captcha: { name: "captcha", limit: 30, windowSeconds: 600 },
  upload: { name: "upload", limit: 30, windowSeconds: 600 },
  adminWrite: { name: "admin_write", limit: 60, windowSeconds: 600 },
  verifyEmail: { name: "verify_email", limit: 10, windowSeconds: 900 },
  changePassword: { name: "change_pw", limit: 5, windowSeconds: 900 },
} satisfies Record<string, RateRule>;

/// 检查并递增计数。超限抛出 429。subjectHash 应为 IP 哈希或账号哈希，不存原文。
export async function consumeRate(
  env: Env,
  rule: RateRule,
  subject: string,
): Promise<void> {
  const subjectHash = await sha256Hex(subject);
  const key = `rl:${rule.name}:${subjectHash}`;
  const raw = await env.KV.get(key);
  const count = raw ? Number(raw) : 0;

  if (count >= rule.limit) {
    throw err.rateLimited(rule.windowSeconds);
  }
  await env.KV.put(key, String(count + 1), {
    expirationTtl: Math.max(rule.windowSeconds, 60),
  });
}

/// 读取当前计数（不递增），用于判断是否需要额外延迟
export async function currentRate(env: Env, rule: RateRule, subject: string): Promise<number> {
  const subjectHash = await sha256Hex(subject);
  const raw = await env.KV.get(`rl:${rule.name}:${subjectHash}`);
  return raw ? Number(raw) : 0;
}

/// 成功后清零（例如登录成功后清除账号级失败计数）
export async function resetRate(env: Env, rule: RateRule, subject: string): Promise<void> {
  const subjectHash = await sha256Hex(subject);
  await env.KV.delete(`rl:${rule.name}:${subjectHash}`);
}

/// 登录失败后的递增延迟（毫秒），防止暴力破解。上限 2 秒，避免占用 Worker 时长。
export function failureDelayMs(failures: number): number {
  if (failures <= 2) return 0;
  return Math.min(2000, 250 * 2 ** (failures - 3));
}

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
