/// 图片验证码：服务端生成、答案 HMAC 后存 KV、一次性使用、有最大尝试次数。
/// 安全性弱于 Cloudflare Turnstile，生产环境建议切换（见 src/lib/turnstile.ts 适配器）。
import type { Env, Limits } from "../env";
import { readLimits } from "../env";
import { hmacHex, randomBytes, randomToken, bytesToHex } from "./crypto";
import { AppError, CAPTCHA_FAILED } from "./errors";
import { renderCaptchaSvg } from "./captcha-svg";
import { hashIp } from "./audit";

/// 排除易混淆字符：0 O 1 I L
export const CAPTCHA_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const CAPTCHA_MIN_LEN = 4;
const CAPTCHA_MAX_LEN = 6;

interface CaptchaRecord {
  /** HMAC(CAPTCHA_SECRET, captchaId + ":" + answer)，明文答案不入库 */
  answerHash: string;
  attempts: number;
  /** 绑定签发时的 IP 哈希，换 IP 使用视为可疑 */
  ipHash: string | null;
  expiresAt: number;
}

function randomAnswer(): string {
  const len =
    CAPTCHA_MIN_LEN + (randomBytes(1)[0]! % (CAPTCHA_MAX_LEN - CAPTCHA_MIN_LEN + 1));
  const bytes = randomBytes(len);
  let out = "";
  for (const b of bytes) out += CAPTCHA_ALPHABET[b % CAPTCHA_ALPHABET.length];
  return out;
}

/// 签发验证码：返回 captchaId 与 SVG 图片
export async function issueCaptcha(
  env: Env,
  ip: string | null,
): Promise<{ captchaId: string; image: string; mime: "image/svg+xml" }> {
  const limits = readLimits(env);
  const captchaId = randomToken(18); // 24 字符，不可猜测
  const answer = randomAnswer();
  const answerHash = await hmacHex(env.CAPTCHA_SECRET, `${captchaId}:${answer}`);
  const ipHash = await hashIp(env, ip);

  const record: CaptchaRecord = {
    answerHash,
    attempts: 0,
    ipHash,
    expiresAt: Math.floor(Date.now() / 1000) + limits.captchaTtlSeconds,
  };
  await env.KV.put(`captcha:${captchaId}`, JSON.stringify(record), {
    expirationTtl: limits.captchaTtlSeconds,
  });

  const svg = renderCaptchaSvg(answer, bytesToHex(randomBytes(4)));
  // 答案只存在于局部变量中，结束后不再保留。
  return { captchaId, image: svg, mime: "image/svg+xml" };
}

/// 校验验证码。成功或超过最大尝试次数后立即删除记录（一次性）。
/// 失败统一返回 CAPTCHA_FAILED，不区分"不存在/过期/答错"，防止探测。
export async function verifyCaptcha(
  env: Env,
  ip: string | null,
  captchaId: string,
  answer: string,
): Promise<void> {
  const limits: Limits = readLimits(env);
  const key = `captcha:${captchaId}`;
  const raw = await env.KV.get(key);
  if (!raw) throw new AppError(422, "captcha_failed", CAPTCHA_FAILED);

  let record: CaptchaRecord;
  try {
    record = JSON.parse(raw) as CaptchaRecord;
  } catch {
    await env.KV.delete(key);
    throw new AppError(422, "captcha_failed", CAPTCHA_FAILED);
  }

  // 先删除再判断：避免并发重放（KV 非原子，尽力而为，并结合速率限制）
  await env.KV.delete(key);

  const expected = await hmacHex(env.CAPTCHA_SECRET, `${captchaId}:${answer}`);
  const ok = expected === record.answerHash;
  if (ok) return;

  const attempts = record.attempts + 1;
  if (attempts < limits.captchaMaxAttempts) {
    const remaining = Math.max(record.expiresAt - Math.floor(Date.now() / 1000), 60);
    await env.KV.put(key, JSON.stringify({ ...record, attempts }), {
      expirationTtl: remaining,
    });
  }
  // 超过次数：记录已删除，验证码失效
  throw new AppError(422, "captcha_failed", CAPTCHA_FAILED);
}
