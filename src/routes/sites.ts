/// 站点管理与上传 API。普通用户只能操作自己的站点；越权一律 404（不暴露站点是否存在）。
import { Hono } from "hono";
import { z } from "zod";
import type { AppEnv } from "../middleware/auth";
import { clientIp, requireAuth } from "../middleware/auth";
import { readJson } from "../lib/http";
import { err, AppError } from "../lib/errors";
import { SiteNameSchema, CaptchaIdSchema, CaptchaAnswerSchema, IdParamSchema, parseOrThrow } from "../lib/validate";
import { consumeRate, RULES } from "../lib/ratelimit";
import { audit } from "../lib/audit";
import { getConfig, readLimits, type Limits } from "../config";
import { nowSec } from "../auth/session";
import { getCaptchaProvider } from "../lib/turnstile";
import { normalizeUploadPath } from "../sites/paths";
import { classifyFile } from "../sites/filetypes";
import { scanContent } from "../sites/content";
import {
  countActiveSites,
  insertSite,
  getSite,
  listSitesByOwner,
  listFileRows,
  stageObjects,
  commitStaged,
  checkQuota,
  deleteObjects,
  softDeleteSite,
  newSiteId,
  newUploadId,
  siteUrl,
  type SiteRow,
  type FileRow,
} from "../sites/store";
import type { Env } from "../env";

export const siteRoutes = new Hono<AppEnv>();

const CreateSiteSchema = z.object({ name: SiteNameSchema });
const UploadFormSchema = z.object({ captchaId: CaptchaIdSchema, captchaAnswer: CaptchaAnswerSchema });

function serializeSite(s: SiteRow) {
  return {
    id: s.id,
    name: s.name,
    status: s.status,
    url: siteUrl(s.id),
    totalBytes: s.total_bytes,
    fileCount: s.file_count,
    createdAt: s.created_at,
    updatedAt: s.updated_at,
  };
}

siteRoutes.use("*", requireAuth());

siteRoutes.post("/", async (c) => {
  const user = c.get("user");
  const input = parseOrThrow(CreateSiteSchema, await readJson(c));
  const max = getConfig().sites.maxPerUser;
  if ((await countActiveSites(c.env, user.id)) >= max) {
    throw err.conflict("site_limit", `站点数量已达上限（${max}）`);
  }
  const id = newSiteId();
  await insertSite(c.env, { id, ownerId: user.id, name: input.name, now: nowSec() });
  await audit(c.env, clientIp(c), { actorId: user.id, action: "site.create", target: id, result: "ok" });
  const site = await getSite(c.env, id, user.id);
  return c.json({ site: serializeSite(site!) }, 201);
});

siteRoutes.get("/", async (c) => {
  const sites = await listSitesByOwner(c.env, c.get("user").id);
  return c.json({ sites: sites.map(serializeSite) });
});

siteRoutes.delete("/:siteId", async (c) => {
  const user = c.get("user");
  const siteId = parseOrThrow(IdParamSchema, c.req.param("siteId"));
  const site = await getSite(c.env, siteId, user.id);
  if (!site) throw err.notFound();
  await softDeleteSite(c.env, site.id, nowSec());
  await audit(c.env, clientIp(c), { actorId: user.id, action: "site.delete", target: site.id, result: "ok" });
  return c.json({ ok: true });
});

/// 校验并读取全部上传文件。任何一个文件不合规都会抛错（整批拒绝，不做部分写入）。
async function validateBatch(
  files: File[],
  limits: Limits,
  existing: FileRow[],
): Promise<{ path: string; contentType: string; ext: string; bytes: Uint8Array }[]> {
  let totalIncoming = 0;
  const requestPaths = new Set<string>();
  const requestLower = new Set<string>();
  const prepared: { path: string; contentType: string; ext: string; bytes: Uint8Array }[] = [];

  for (const file of files) {
    const path = normalizeUploadPath(file.name);
    if (requestPaths.has(path)) throw err.badRequest("duplicate_path", "同一次上传中路径重复");
    // 大小写不敏感冲突（A.html 与 a.html 在多数文件系统与生态工具中会混淆）
    if (requestLower.has(path.toLowerCase())) throw err.badRequest("case_conflict", "路径大小写冲突");
    requestPaths.add(path);
    requestLower.add(path.toLowerCase());

    const { ext, contentType } = classifyFile(path);
    if (file.size > limits.maxFileBytes) {
      throw new AppError(413, "file_too_large", `单个文件超过 ${limits.maxFileBytes} 字节上限`);
    }
    totalIncoming += file.size;
    if (totalIncoming > limits.maxUploadBytes) {
      throw new AppError(413, "upload_too_large", "本次上传总大小超过限制");
    }

    const bytes = new Uint8Array(await file.arrayBuffer());
    scanContent(ext, bytes);
    prepared.push({ path, contentType, ext, bytes });
  }

  // 与已有文件的大小写冲突（同路径替换是允许的）
  for (const p of prepared) {
    for (const e of existing) {
      if (e.path !== p.path && e.path.toLowerCase() === p.path.toLowerCase()) {
        throw err.conflict("case_conflict", "与已有文件路径大小写冲突");
      }
    }
  }

  checkQuota(
    limits,
    existing.map((e) => ({ path: e.path, size: e.size })),
    prepared.map((p) => ({ path: p.path, size: p.bytes.byteLength })),
  );
  return prepared;
}

/// 上传：multipart/form-data，可一次多文件。每个 File 的 name 即目标相对路径，例如 "css/app.css"。
/// 顺序：限流 → 归属 → 验证码 → 逐文件校验（路径/类型/内容）→ 配额 → 暂存 → 原子提交 → 清理旧对象
siteRoutes.post("/:siteId/upload", async (c) => {
  const user = c.get("user");
  const ip = clientIp(c);
  const siteId = parseOrThrow(IdParamSchema, c.req.param("siteId"));
  const limits = readLimits();

  await consumeRate(c.env, RULES.upload, user.id);

  const site = await getSite(c.env, siteId, user.id);
  if (!site) throw err.notFound();
  if (site.status !== "active") throw err.conflict("site_inactive", "站点不可用");

  const declared = Number(c.req.header("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > limits.maxUploadBytes + 256 * 1024) {
    throw new AppError(413, "upload_too_large", "本次上传总大小超过限制");
  }

  let form: FormData;
  try {
    form = await c.req.formData();
  } catch {
    throw err.badRequest("invalid_form", "请使用 multipart/form-data 上传");
  }

  const captcha = parseOrThrow(UploadFormSchema, {
    captchaId: form.get("captchaId"),
    captchaAnswer: form.get("captchaAnswer"),
  });
  await getCaptchaProvider(c.env).verify(c.env, ip, captcha);

  const files = form.getAll("files").filter((e): e is File => e instanceof File);
  const maxFiles = getConfig().upload.maxFilesPerRequest;
  if (files.length === 0) throw err.badRequest("no_files", "未选择文件");
  if (files.length > maxFiles) {
    throw err.badRequest("too_many_in_request", `单次最多上传 ${maxFiles} 个文件`);
  }

  const existing = await listFileRows(c.env, site.id);

  let prepared: Awaited<ReturnType<typeof validateBatch>>;
  try {
    prepared = await validateBatch(files, limits, existing);
  } catch (e) {
    // 被拒绝的上传同样记审计（只记录错误码，不记录文件内容或名称）
    const code = e instanceof AppError ? e.code : "unknown";
    await audit(c.env, ip, { actorId: user.id, action: "site.upload", target: `${site.id}:${code}`, result: "denied" });
    throw e;
  }

  const uploadId = newUploadId();
  const staged = await stageObjects(
    c.env,
    user.id,
    site.id,
    uploadId,
    prepared.map((p) => ({ path: p.path, bytes: p.bytes, contentType: p.contentType })),
  );

  let replaced: string[];
  try {
    replaced = await commitStaged(c.env as Env, site.id, staged, nowSec());
  } catch {
    // 提交失败：回滚本次暂存对象，数据库保持原状
    await deleteObjects(c.env, staged.map((s) => s.r2Key));
    throw new AppError(500, "commit_failed", "保存失败，请重试");
  }
  await deleteObjects(c.env, replaced);

  await audit(c.env, ip, { actorId: user.id, action: "site.upload", target: site.id, result: "ok" });

  return c.json(
    {
      siteUrl: siteUrl(site.id),
      uploaded: staged.map((s) => ({ path: s.path, size: s.size, contentType: s.contentType })),
    },
    201,
  );
});
