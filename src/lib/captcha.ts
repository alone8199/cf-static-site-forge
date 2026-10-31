/// 图片验证码：服务端生成、答案 HMAC 后存 KV、一次性使用、有最大尝试次数。
/// 字符集、长度、TTL、尝试次数均来自 config/app.config.ts。
/// 安全性弱于 Cloudflare Turnstile，生产建议切换（见 src/lib/turnstile.ts）。
import type { Env } from "../env";
import { getConfig, readLimits, type Limits } from "../config";
import { hmacHex, randomBytes, randomToken, bytesToB64 } from "./crypto";
import { AppError, CAPTCHA_FAILED } from "./errors";
import { renderCaptchaSvg } from "./captcha-svg";
import { hashIp } from "./audit";

interface CaptchaRecord {
  /** HMAC(CAPTCHA_SECRET, captchaId + ":" + answer)，明文答案不入库 */
  answerHash: string;
  attempts: number;
  ipHash: string | null;
  expiresAt: number;
}

function randomAnswer(): string {
  const cfg = getConfig().captcha;
  const span = cfg.maxLength - cfg.minLength + 1;
  const len = cfg.minLength + (randomBytes(1)[0]! % span);
  let out = "";
  for (const b of randomBytes(len)) out += cfg.alphabet[b % cfg.alphabet.length]!;
  return out;
}

/// 签发验证码。返回 captchaId 与 SVG 文本（答案不返回、不记录）。
export async function issueCaptcha(
  env: Env,
  ip: string | null,
): Promise<{ captchaId: string; svg: string }> {
  const ttl = getConfig().captcha.ttlSeconds;
  const captchaId = randomToken(18);
  const answer = randomAnswer();
  const record: CaptchaRecord = {
    answerHash: await hmacHex(env.CAPTCHA_SECRET, `${captchaId}:${answer}`),
    attempts: 0,
    ipHash: await hashIp(env, ip),
    expiresAt: Math.floor(Date.now() / 1000) + ttl,
  };
  await env.KV.put(`captcha:${captchaId}`, JSON.stringify(record), { expirationTtl: Math.max(ttl, 60) });
  const svg = renderCaptchaSvg(answer, bytesToB64(randomBytes(6)));
  return { captchaId, svg };
}

/// 校验验证码。成功或超过最大尝试次数后记录立即删除（一次性）。
/// 所有失败统一返回 CAPTCHA_FAILED，不区分不存在/过期/答错。
export async function verifyCaptcha(
  env: Env,
  _ip: string | null,
  captchaId: string,
  answer: string,
): Promise<void> {
  const limits: Limits = readLimits();
  const key = `captcha:${captchaId}`;
  const raw = await env.KV.get(key);
  if (!raw) throw new AppError(422, "captcha_failed", CAPTCHA_FAILED);

  // 先删除再判断，尽量缩小并发重放窗口（KV 非原子，配合速率限制）
  await env.KV.delete(key);

  let record: CaptchaRecord;
  try {
    record = JSON.parse(raw) as CaptchaRecord;
  } catch {
    throw new AppError(422, "captcha_failed", CAPTCHA_FAILED);
  }

  const expected = await hmacHex(env.CAPTCHA_SECRET, `${captchaId}:${answer}`);
  if (expected === record.answerHash) return;

  const attempts = record.attempts + 1;
  if (attempts < limits.captchaMaxAttempts) {
    const remaining = Math.max(record.expiresAt - Math.floor(Date.now() / 1000), 60);
    await env.KV.put(key, JSON.stringify({ ...record, attempts }), { expirationTtl: remaining });
  }
  throw new AppError(422, "captcha_failed", CAPTCHA_FAILED);
}
