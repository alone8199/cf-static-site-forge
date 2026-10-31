/// GET /api/captcha：签发图片验证码。返回 { captchaId, image }，image 为 SVG 的 data URI。
import { Hono } from "hono";
import type { AppEnv } from "../middleware/auth";
import { clientIp } from "../middleware/auth";
import { consumeRate, RULES } from "../lib/ratelimit";
import { issueCaptcha } from "../lib/captcha";
import { bytesToB64 } from "../lib/crypto";

export const captchaRoutes = new Hono<AppEnv>();

captchaRoutes.get("/", async (c) => {
  const ip = clientIp(c);
  await consumeRate(c.env, RULES.captcha, ip ?? "unknown");
  const { captchaId, image } = await issueCaptcha(c.env, ip);
  const dataUri = `data:image/svg+xml;base64,${bytesToB64(new TextEncoder().encode(image))}`;
  c.header("Cache-Control", "no-store");
  return c.json({ captchaId, image: dataUri });
});
