/// HTTP 辅助：安全解析 JSON、统一响应头、安全头注入。
import type { Context } from "hono";
import { AppError } from "./errors";

const MAX_JSON_BYTES = 16 * 1024;

export async function readJson(c: Context): Promise<Record<string, unknown>> {
  const len = Number(c.req.header("content-length") ?? "0");
  if (Number.isFinite(len) && len > MAX_JSON_BYTES) {
    throw new AppError(413, "payload_too_large", "请求体过大");
  }
  const ct = c.req.header("content-type") ?? "";
  if (!ct.toLowerCase().startsWith("application/json")) {
    throw new AppError(415, "unsupported_media_type", "需要 application/json");
  }
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    throw new AppError(400, "invalid_json", "请求体不是合法 JSON");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new AppError(400, "invalid_body", "请求体格式错误");
  }
  return body as Record<string, unknown>;
}

/// 主应用（API / 前端）安全响应头：严格 CSP、禁止嵌入、禁止 MIME 嗅探
export const APP_SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "Cache-Control": "no-store",
};

export function applyAppHeaders(c: Context): void {
  for (const [k, v] of Object.entries(APP_SECURITY_HEADERS)) c.header(k, v);
}
