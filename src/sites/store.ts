/// 站点与文件的 D1 / Workers KV 操作。
/// 不变量：
///   - 存储键 只由服务端生成：users/{ownerId}/sites/{siteId}/{uploadId}/{normalizedPath}
///   - 用户路径只作为 files.path 元数据，不参与存储键拼接
///   - 提交（D1 batch = 事务）成功后才替换生效；失败则删除本次暂存的文件（回滚）
import type { Env } from "../env";
import { randomId, sha256Hex } from "../lib/crypto";
import { AppError } from "../lib/errors";
import { getConfig, type Limits } from "../config";

export interface SiteRow {
  id: string;
  owner_id: string;
  name: string;
  status: "active" | "suspended" | "deleted";
  total_bytes: number;
  file_count: number;
  created_at: number;
  updated_at: number;
}

export interface StagedFile {
  path: string;
  storageKey: string;
  size: number;
  sha256: string;
  contentType: string;
}

export async function countActiveSites(env: Env, ownerId: string): Promise<number> {
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM sites WHERE owner_id = ?1 AND status != 'deleted'`,
  )
    .bind(ownerId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

export async function insertSite(
  env: Env,
  args: { id: string; ownerId: string; name: string; now: number },
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO sites (id, owner_id, name, status, total_bytes, file_count, created_at, updated_at)
     VALUES (?1, ?2, ?3, 'active', 0, 0, ?4, ?4)`,
  )
    .bind(args.id, args.ownerId, args.name, args.now)
    .run();
}

/// 按 ID 查站点。ownerId 非空时同时校验归属（越权统一返回 null → 上层 404）。
export async function getSite(env: Env, siteId: string, ownerId?: string): Promise<SiteRow | null> {
  if (ownerId) {
    return env.DB.prepare(
      `SELECT * FROM sites WHERE id = ?1 AND owner_id = ?2 AND status != 'deleted'`,
    )
      .bind(siteId, ownerId)
      .first<SiteRow>();
  }
  return env.DB.prepare(`SELECT * FROM sites WHERE id = ?1 AND status != 'deleted'`)
    .bind(siteId)
    .first<SiteRow>();
}

export async function listSitesByOwner(env: Env, ownerId: string): Promise<SiteRow[]> {
  const res = await env.DB.prepare(
    `SELECT * FROM sites WHERE owner_id = ?1 AND status != 'deleted' ORDER BY created_at DESC`,
  )
    .bind(ownerId)
    .all<SiteRow>();
  return res.results ?? [];
}

export interface FileRow {
  path: string;
  storage_key: string;
  size: number;
  content_type: string;
}

export async function listFileRows(env: Env, siteId: string): Promise<FileRow[]> {
  const res = await env.DB.prepare(
    `SELECT path, storage_key, size, content_type FROM files WHERE site_id = ?1`,
  )
    .bind(siteId)
    .all<FileRow>();
  return res.results ?? [];
}

/// 暂存：把对象写入本次上传专属前缀。任一失败则删除已写入的对象并抛错。
export async function stageObjects(
  env: Env,
  ownerId: string,
  siteId: string,
  uploadId: string,
  files: { path: string; bytes: Uint8Array; contentType: string }[],
): Promise<StagedFile[]> {
  const staged: StagedFile[] = [];
  try {
    for (const f of files) {
      const storageKey = `users/${ownerId}/sites/${siteId}/${uploadId}/${f.path}`;
      // KV 单值上限 25 MiB（config 中 maxFileBytes 已限制在此之内）
      await env.FILES_KV.put(storageKey, f.bytes);
      staged.push({
        path: f.path,
        storageKey,
        size: f.bytes.byteLength,
        sha256: await sha256Hex(f.bytes),
        contentType: f.contentType,
      });
    }
    return staged;
  } catch {
    await deleteObjects(env, staged.map((s) => s.storageKey));
    throw new AppError(500, "upload_failed", "上传失败，请重试");
  }
}

/// 原子提交：一个 D1 batch（事务）内完成 upsert + 重算站点总量与文件数。
/// 返回被替换的旧 存储键（提交成功后再清理）。
export async function commitStaged(env: Env, siteId: string, staged: StagedFile[], now: number): Promise<string[]> {
  const existing = await listFileRows(env, siteId);
  const oldByPath = new Map(existing.map((r) => [r.path, r.storage_key]));

  const stmts = staged.map((f) =>
    env.DB.prepare(
      `INSERT INTO files (site_id, path, storage_key, size, sha256, content_type, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
       ON CONFLICT(site_id, path) DO UPDATE SET
         storage_key = excluded.storage_key, size = excluded.size, sha256 = excluded.sha256,
         content_type = excluded.content_type, created_at = excluded.created_at`,
    ).bind(siteId, f.path, f.storageKey, f.size, f.sha256, f.contentType, now),
  );
  stmts.push(
    env.DB.prepare(
      `UPDATE sites SET
         total_bytes = (SELECT COALESCE(SUM(size), 0) FROM files WHERE site_id = ?1),
         file_count  = (SELECT COUNT(*) FROM files WHERE site_id = ?1),
         updated_at  = ?2
       WHERE id = ?1`,
    ).bind(siteId, now),
  );
  await env.DB.batch(stmts);

  const replaced: string[] = [];
  for (const f of staged) {
    const old = oldByPath.get(f.path);
    if (old && old !== f.storageKey) replaced.push(old);
  }
  return replaced;
}

/// 配额检查：合并“已有文件（被替换的除外）”与“本次新文件”，检查数量与总量。
export function checkQuota(
  limits: Limits,
  existing: { path: string; size: number }[],
  incoming: { path: string; size: number }[],
): void {
  const merged = new Map<string, number>();
  for (const e of existing) merged.set(e.path, e.size);
  for (const f of incoming) merged.set(f.path, f.size);

  let total = 0;
  for (const s of merged.values()) total += s;

  if (merged.size > limits.maxSiteFiles) {
    throw new AppError(413, "too_many_files", `站点文件数量超过上限（${limits.maxSiteFiles}）`);
  }
  if (total > limits.maxSiteBytes) {
    throw new AppError(413, "site_quota_exceeded", "站点总容量超过上限");
  }
}

export async function deleteObjects(env: Env, keys: string[]): Promise<void> {
  for (const key of keys) {
    try {
      await env.FILES_KV.delete(key);
    } catch {
      // 清理失败只会留下孤儿对象，不影响主流程；不记录 key 以免泄露结构
    }
  }
}

/// 软删除站点：标记 deleted、删除文件元数据，并清理 存储对象
export async function softDeleteSite(env: Env, siteId: string, now: number): Promise<void> {
  const rows = await listFileRows(env, siteId);
  await env.DB.batch([
    env.DB.prepare(`UPDATE sites SET status = 'deleted', total_bytes = 0, file_count = 0, updated_at = ?2 WHERE id = ?1`).bind(siteId, now),
    env.DB.prepare(`DELETE FROM files WHERE site_id = ?1`).bind(siteId),
  ]);
  await deleteObjects(env, rows.map((r) => r.storage_key));
}

export function newSiteId(): string {
  return randomId(16);
}

export function newUploadId(): string {
  return randomId(8);
}

/// 站点访问地址（域名与协议来自配置）
export function siteUrl(siteId: string): string {
  const { scheme, rootDomain } = getConfig().sites;
  return `${scheme}://${siteId}.${rootDomain}/`;
}
