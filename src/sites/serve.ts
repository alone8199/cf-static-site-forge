/// 用户站点的静态文件服务（独立子域 {siteId}.{rootDomain}）。
/// 安全要点：
///   - 只处理 GET/HEAD；不设置任何 Cookie；不读取主应用 Cookie（主应用 Cookie 为 host-only 的 __Host- Cookie）
///   - 路径经规范化后仅用于查询 files 元数据，存储键 来自数据库记录，绝不由请求路径拼接
///   - 响应头（沙箱 CSP、nosniff 等）来自配置
import type { Env } from "../env";
import { getConfig } from "../config";
import { resolveRequestPath } from "./paths";

const SITE_ID_RE = /^[a-f0-9]{32}$/;

/// 返回：站点 ID（字符串）、null（属于站点域但非法，应 404）、undefined（不属于站点域，交给主应用）
export function siteIdFromHost(hostname: string, rootDomain: string): string | null | undefined {
  const root = rootDomain.toLowerCase();
  const host = hostname.toLowerCase();
  if (host === root) return null;
  if (!host.endsWith("." + root)) return undefined;
  const label = host.slice(0, -(root.length + 1));
  if (label.includes(".")) return null; // 只允许单层子域
  return SITE_ID_RE.test(label) ? label : null;
}

function siteHeaders(): Record<string, string> {
  const r = getConfig().siteResponse;
  return {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": r.permissionsPolicy,
    "Content-Security-Policy": r.contentSecurityPolicy,
    "X-Frame-Options": "SAMEORIGIN",
    "Cross-Origin-Resource-Policy": "same-site",
  };
}

function plain(status: number, body: string, extra: Record<string, string> = {}): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", ...siteHeaders(), ...extra },
  });
}

export async function serveSite(request: Request, env: Env, siteId: string): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return plain(405, "Method Not Allowed", { Allow: "GET, HEAD" });
  }

  const path = resolveRequestPath(new URL(request.url).pathname);
  if (!path) return plain(404, "Not Found");

  const row = await env.DB.prepare(
    `SELECT f.storage_key AS storage_key, f.content_type AS content_type, f.size AS size,
            f.sha256 AS sha256, s.status AS status
       FROM files f JOIN sites s ON s.id = f.site_id
      WHERE f.site_id = ?1 AND f.path = ?2`,
  )
    .bind(siteId, path)
    .first<{ storage_key: string; content_type: string; size: number; sha256: string; status: string }>();

  if (!row || row.status !== "active") return plain(404, "Not Found");

  const cfg = getConfig().siteResponse;
  const etag = `"${row.sha256}"`;
  const isHtml = row.content_type.startsWith("text/html");
  const headers: Record<string, string> = {
    "Content-Type": row.content_type,
    "Content-Length": String(row.size),
    ETag: etag,
    "Cache-Control": isHtml ? cfg.htmlCacheControl : cfg.assetCacheControl,
    ...siteHeaders(),
  };

  if (request.headers.get("if-none-match") === etag) {
    return new Response(null, { status: 304, headers });
  }
  if (request.method === "HEAD") {
    return new Response(null, { status: 200, headers });
  }
  const body = await env.FILES_KV.get(row.storage_key, { type: "stream" });
  if (!body) return plain(404, "Not Found");
  return new Response(body, { status: 200, headers });
}
