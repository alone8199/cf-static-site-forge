/// 用户站点的静态文件服务（独立子域 {siteId}.{SITES_ROOT_DOMAIN}）。
/// 安全要点：
///   - 只处理 GET/HEAD；不设置任何 Cookie；不读取主应用 Cookie（主应用 Cookie 是 host-only 的 __Host- Cookie）
///   - 路径经规范化后仅用于查询 files 元数据，R2 key 来自数据库记录，绝不由请求路径拼接
///   - 返回 nosniff、沙箱 CSP、严格 Referrer/Permissions 策略
import type { Env } from "../env";
import { resolveRequestPath } from "./paths";

const SITE_ID_RE = /^[a-f0-9]{32}$/;

export function siteIdFromHost(hostname: string, rootDomain: string): string | null | undefined {
  const root = rootDomain.toLowerCase();
  const host = hostname.toLowerCase();
  if (host === root) return null; // 站点根域本身，不提供服务
  if (!host.endsWith("." + root)) return undefined; // 不属于站点域，交给主应用
  const label = host.slice(0, -(root.length + 1));
  // 只允许单层子域，防止 a.b.sites.example.com 之类的混淆
  if (label.includes(".")) return null;
  return SITE_ID_RE.test(label) ? label : null;
}

const SITE_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  // 用户页面处于沙箱中：默认不具备同源权限，即使有 XSS 也无法访问其他源的数据
  "Content-Security-Policy": "sandbox allow-scripts allow-forms allow-popups allow-downloads",
  "X-Frame-Options": "SAMEORIGIN",
  "Cross-Origin-Resource-Policy": "same-site",
};

function notFound(): Response {
  return new Response("Not Found", {
    status: 404,
    headers: { "Content-Type": "text/plain; charset=utf-8", ...SITE_HEADERS },
  });
}

export async function serveSite(request: Request, env: Env, siteId: string): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method Not Allowed", {
      status: 405,
      headers: { Allow: "GET, HEAD", ...SITE_HEADERS },
    });
  }

  const url = new URL(request.url);
  const path = resolveRequestPath(url.pathname);
  if (!path) return notFound();

  const row = await env.DB.prepare(
    `SELECT f.r2_key AS r2_key, f.content_type AS content_type, f.size AS size,
            f.sha256 AS sha256, s.status AS status
       FROM files f JOIN sites s ON s.id = f.site_id
      WHERE f.site_id = ?1 AND f.path = ?2`,
  )
    .bind(siteId, path)
    .first<{ r2_key: string; content_type: string; size: number; sha256: string; status: string }>();

  if (!row || row.status !== "active") return notFound();

  const etag = `"${row.sha256}"`;
  const isHtml = row.content_type.startsWith("text/html");
  const headers: Record<string, string> = {
    "Content-Type": row.content_type,
    "Content-Length": String(row.size),
    ETag: etag,
    "Cache-Control": isHtml ? "no-cache" : "public, max-age=3600",
    ...SITE_HEADERS,
  };

  if (request.headers.get("if-none-match") === etag) {
    return new Response(null, { status: 304, headers });
  }

  if (request.method === "HEAD") {
    const meta = await env.SITES_BUCKET.head(row.r2_key);
    if (!meta) return notFound();
    return new Response(null, { status: 200, headers });
  }

  const obj = await env.SITES_BUCKET.get(row.r2_key);
  if (!obj) return notFound();
  return new Response(obj.body, { status: 200, headers });
}
