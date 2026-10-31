/// 验证码适配器接口。当前实现：图片验证码（image）。
/// Turnstile 适配器已预留：设置 CAPTCHA_PROVIDER=turnstile 并实现 verify() 即可切换。
/// 注意：Turnstile 需要前端渲染 widget 并提交 token，本文件只提供服务端校验骨架。
import type { Env } from "../env";
import { getConfig } from "../config";
import { AppError, CAPTCHA_FAILED } from "./errors";
import { verifyCaptcha } from "./captcha";

export interface CaptchaInput {
  captchaId?: string;
  captchaAnswer?: string;
  /** Turnstile 使用的 token（字段名 cf-turnstile-response） */
  turnstileToken?: string;
}

export interface CaptchaProvider {
  name: "image" | "turnstile";
  verify(env: Env, ip: string | null, input: CaptchaInput): Promise<void>;
}

export const imageCaptchaProvider: CaptchaProvider = {
  name: "image",
  async verify(env, ip, input) {
    if (!input.captchaId || !input.captchaAnswer) {
      throw new AppError(422, "captcha_required", "请输入验证码");
    }
    await verifyCaptcha(env, ip, input.captchaId, input.captchaAnswer);
  },
};

/// Turnstile 适配器（预留）。调用 siteverify 接口校验 token。
export const turnstileCaptchaProvider: CaptchaProvider = {
  name: "turnstile",
  async verify(env, ip, input) {
    if (!input.turnstileToken) {
      throw new AppError(422, "captcha_required", "请完成人机验证");
    }
    const secret = env.TURNSTILE_SECRET;
    if (!secret) throw new AppError(503, "unavailable", "人机验证未配置");
    const body = new FormData();
    body.set("secret", secret);
    body.set("response", input.turnstileToken);
    if (ip) body.set("remoteip", ip);
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body,
    });
    const data = (await res.json()) as { success?: boolean };
    if (!data.success) throw new AppError(422, "captcha_failed", CAPTCHA_FAILED);
  },
};

export function getCaptchaProvider(env: Env): CaptchaProvider {
  return getConfig().captcha.provider === "turnstile" ? turnstileCaptchaProvider : imageCaptchaProvider;
}
