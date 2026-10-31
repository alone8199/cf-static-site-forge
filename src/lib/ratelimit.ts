/// 基于 KV 的固定窗口速率限制。规则来自 config/app.config.ts 的 rateLimits。
/// 注意：KV 最终一致、非原子。能有效拦截暴力破解与脚本滥用，但不是精确计数；
/// 生产环境建议同时启用 Cloudflare Rate Limiting 规则（见 README）。
import type { Env } from "../env";
import { err } from "./errors";
import { sha256Hex } from "./crypto";
import { getConfig, type AppConfig } from "../config";

export interface RateRule {
  name: string;
  limit: number;
  windowSeconds: number;
}

type RuleName = keyof AppConfig["rateLimits"];

/// 通过 Proxy 按需读取配置，保证规则与 config/app.config.ts 始终一致
export const RULES = new Proxy({} as Record<RuleName, RateRule>, {
  get(_target, key) {
    const name = String(key) as RuleName;
    const cfg = getConfig().rateLimits[name];
    if (!cfg) throw new Error(`unknown rate rule: ${name}`);
    return { name, limit: cfg.limit, windowSeconds: cfg.windowSeconds } satisfies RateRule;
  },
});

/// 检查并递增计数。超限抛出 429。subject 为 IP 或账号等，只存哈希。
export async function consumeRate(env: Env, rule: RateRule, subject: string): Promise<void> {
  const key = `rl:${rule.name}:${await sha256Hex(subject)}`;
  const raw = await env.KV.get(key);
  const count = raw ? Number(raw) : 0;
  if (count >= rule.limit) throw err.rateLimited(rule.windowSeconds);
  await env.KV.put(key, String(count + 1), { expirationTtl: Math.max(rule.windowSeconds, 60) });
}

/// 成功后清零（例如登录成功后清除账号级失败计数）
export async function resetRate(env: Env, rule: RateRule, subject: string): Promise<void> {
  await env.KV.delete(`rl:${rule.name}:${await sha256Hex(subject)}`);
}

/// 登录失败后的递增延迟（毫秒），上限来自配置。
export function failureDelayMs(failures: number): number {
  const max = getConfig().auth.failureDelayMaxMs;
  if (failures <= 2) return 0;
  return Math.min(max, 250 * 2 ** (failures - 3));
}

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
