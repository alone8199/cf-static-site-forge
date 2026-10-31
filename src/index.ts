/// Worker 入口：按 Host 分流
///   - {siteId}.{rootDomain}  → 用户静态站点（只读、沙箱、无 Cookie）
///   - 其它（主应用）          → API 与前端静态资源
import { Hono } from "hono";
import type { Env } from "./env";
import type { AppEnv } from "./middleware/auth";
import { AppError } from "./lib/errors";
import { applyAppHeaders, APP_SECURITY_HEADERS } from "./lib/http";
import { authRoutes } from "./routes/auth";
import { captchaRoutes } from "./routes/captcha";
import { siteRoutes } from "./routes/sites";
import { adminRoutes } from "./routes/admin";
import { bootstrapRoutes } from "./routes/bootstrap";
import { siteIdFromHost, serveSite } from "./sites/serve";
import { nowSec } from "./auth/session";
import { getConfig } from "./config";

const app = new Hono<AppEnv>();

app.use("*", async (c, next) => {
  applyAppHeaders(c);
  await next();
});

app.route("/api/auth", authRoutes);
app.route("/api/captcha", captchaRoutes);
app.route("/api/sites", siteRoutes);
app.route("/api/admin", adminRoutes);
app.route("/api/bootstrap", bootstrapRoutes);

app.get("/api/health", (c) => c.json({ ok: true }));

app.onError((e, c) => {
  if (e instanceof AppError) {
    if (e.retryAfter) c.header("Retry-After", String(e.retryAfter));
    return c.json({ error: { code: e.code, message: e.message } }, e.status);
  }
  // 只记录错误类型，不记录消息与堆栈，防止泄露 SQL、R2 key 或环境变量
  console.error("unhandled_error", e instanceof Error ? e.name : "unknown");
  return c.json({ error: { code: "internal_error", message: "服务器内部错误" } }, 500);
});

app.notFound((c) => c.json({ error: { code: "not_found", message: "资源不存在" } }, 404));

// 前端静态资源（public/）由 Workers Assets 提供；非 API 的未知路径回落到 index.html
app.get("*", async (c) => {
  if (c.req.path.startsWith("/api/")) {
    return c.json({ error: { code: "not_found", message: "资源不存在" } }, 404);
  }
  let res = await c.env.ASSETS.fetch(c.req.raw);
  if (res.status === 404) {
    res = await c.env.ASSETS.fetch(new Request(new URL("/index.html", c.req.url), c.req.raw));
  }
  // 资源响应重新包装，确保主应用安全头（严格 CSP 等）一定附加
  const headers = new Headers(res.headers);
  for (const [k, v] of Object.entries(APP_SECURITY_HEADERS)) headers.set(k, v);
  return new Response(res.body, { status: res.status, headers });
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const hostname = new URL(request.url).hostname;
    const siteId = siteIdFromHost(hostname, getConfig().sites.rootDomain);

    // 站点域永远不进入主应用路由，避免站点请求触达 API 或 Cookie 逻辑
    if (siteId === null) {
      return new Response("Not Found", {
        status: 404,
        headers: { "Content-Type": "text/plain; charset=utf-8", "X-Content-Type-Options": "nosniff" },
      });
    }
    if (siteId !== undefined) return serveSite(request, env, siteId);
    return app.fetch(request, env, ctx);
  },

  /// 定时清理：过期会话、过期验证令牌、超过保留期的审计日志
  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    const now = nowSec();
    const retention = getConfig().audit.retentionDays * 86400;
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM sessions WHERE expires_at < ?1`).bind(now),
      env.DB.prepare(`DELETE FROM email_verifications WHERE expires_at < ?1`).bind(now),
      env.DB.prepare(`DELETE FROM audit_logs WHERE created_at < ?1`).bind(now - retention),
    ]);
  },
};
