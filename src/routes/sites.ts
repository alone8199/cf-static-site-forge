/// 站点管理与上传 API（普通用户只能操作自己的站点；越权一律 404，不暴露站点是否存在）。
import { Hono } from "hono";
import { z } from "zod";
import type { AppEnv } from "../middleware/auth";
import { clientIp, requireAuth } from "../middleware/auth";
import { readJson } from "../lib/http";
import { err, AppError } from "../lib/errors";
import { SiteNameSchema, CaptchaIdSchema, CaptchaAnswerSchema, IdParamSchema, parseOrThrow } from "../lib/validate";
import { consumeRate, RULES } from "../lib/ratelimit";
import { audit } from "../lib/audit";
import { readLimits } from "../env";
import { nowSec } from "../auth/session";
import { getCaptchaProvider } from "../lib/turnstile";
import { normalizeUploadPath } from "../sites/paths";
import { classifyFile } from "../sites/filetypes";
import {
  MAX_SITES_PER_USER,
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
} from "../sites/store";

export const siteRoutes = new Hono<AppEnv>();

const MAX_FILES_PER_REQUEST = 50;

const CreateSiteSchema = z.object({ name: SiteNameSchema });

function serializeSite(env: AppEnv["Bindings"], s: SiteRow) {
  return {
    id: s.id,
    name: s.name,
    status: s.status,
    url: siteUrl(env, s.id),
    totalBytes: s.total_bytes,
    fileCount: s.file_count,
    createdAt: s.created_at,
    updatedAt: s.updated_at,
  };
}

// 所有站点路由都要求登录（含 CSRF）
siteRoutes.use("*", requireAuth());

siteRoutes.post("/", async (c) => {
  const user = c.get("user");
  const input = parseOrThrow(CreateSiteSchema, await readJson(c));
  if ((await countActiveSites(c.env, user.id)) >= MAX_SITES_PER_USER) {
    throw err.conflict("site_limit", `站点数量已达上限（${MAX_SITES_PER_USER}）`);
  }
  const id = newSiteId();
  const now = nowSec();
  await insertSite(c.env, { id, ownerId: user.id, name: input.name, now });
  await audit(c.env, clientIp(c), { actorId: user.id, action: "site.create", target: id, result: "ok" });
  const site = await getSite(c.env, id, user.id);
  return c.json({ site: serializeSite(c.env, site!) }, 201);
});

siteRoutes.get("/", async (c) => {
  const user = c.get("user");
  const sites = await listSitesByOwner(c.env, user.id);
  return c.json({ sites: sites.map((s) => serializeSite(c.env, s)) });
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

/// 上传：multipart/form-data，可一次多文件。
/// - 每个 File 的 name 即目标相对路径，例如 "css/app.css"（前端用 new File([blob], "css/app.css")）
/// - 表单需包含 captchaId 与 captchaAnswer（上传前必须通过验证码）
siteRoutes.post("/:siteId/upload", async (c) => {
  const user = c.get("user");
  const ip = clientIp(c);
  const siteId = parseOrThrow(IdParamSchema, c.req.param("siteId"));
  const limits = readLimits(c.env);

  await consumeRate(c.env, RULES.upload, user.id);

  const site = await getSite(c.env, siteId, user.id);
  if (!site) throw err.notFound();
  if (site.status !== "active") throw err.conflict("site_inactive", "站点不可用");

  // Content-Length 预检，避免读取超大请求体
  const declared = Number(c.req.header("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > limits.maxUploadBytes + 64 * 1024) {
    throw new AppError(413, "upload_too_large", "本次上传总大小超过限制");
  }

  let form: FormData;
  try {
    form = await c.req.formData();
  } catch {
    throw err.badRequest("invalid_form", "请使用 multipart/form-data 上传");
  }

  // 验证码（先于文件处理）
  const captchaInput = parseOrThrow(
    z.object({ captchaId: CaptchaIdSchema, captchaAnswer: CaptchaAnswerSchema }),
    { captchaId: form.get("captchaId"), captchaAnswer: form.get("captchaAnswer") },
  );
  await getCaptchaProvider(c.env).verify(c.env, ip, captchaInput);

  const entries = form.getAll("files");
  const files = entries.filter((e): e is File => e instanceof File);
  if (files.length === 0) throw err.badRequest("no_files", "未选择文件");
  if (files.length > MAX_FILES_PER_REQUEST) {
    throw err.badRequest("too_many_in_request", `单次最多上传 ${MAX_FILES_PER_REQUEST} 个文件`);
  }

  // 逐个校验：路径、类型、单文件大小
  let totalIncoming = 0;
  const seen = new Set<string>();
  const prepared: { path: string; contentType: string; file: File }[] = [];
  for (const file of files) {
    const path = normalizeUploadPath(file.name);
    if (seen.has(path)) throw err.badRequest("duplicate_path", "同一次上传中路径重复");
    seen.add(path);
    const { contentType } = classifyFile(path);
    if (file.size > limits.maxFileBytes) {
      throw new AppError(413, "file_too_large", `单个文件超过 ${limits.maxFileBytes} 字节上限`);
    }
    totalIncoming += file.size;
    prepared.push({ path, contentType, file });
  }
  if (totalIncoming > limits.maxUploadBytes) {
    throw new AppError(413, "upload_too_large", "本次上传总大小超过限制");
  }

  // 配额：替换后的站点总量与文件数
  const existing = await listFileRows(c.env, site.id);
  checkQuota(
    limits,
    site,
    existing.map((e) => ({ path: e.path, size: e.size })),
    prepared.map((p) => ({ path: p.path, size: p.file.size })),
  );

  // 阶段 1：暂存到本次上传专属前缀
  const uploadId = newUploadId();
  const staged = await stageObjects(
    c.env,
    user.id,
    site.id,
    uploadId,
    await Promise.all(
      prepared.map(async (p) => ({
        path: p.path,
        bytes: await p.file.arrayBuffer(),
        contentType: p.contentType,
      })),
    ),
  );

  // 阶段 2：原子提交；失败则回滚已暂存对象
  let replaced: string[];
  try {
    replaced = await commitStaged(c.env, site.id, staged, nowSec());
  } catch {
    await deleteObjects(c.env, staged.map((s) => s.r2Key));
    throw new AppError(500, "commit_failed", "保存失败，请重试");
  }

  // 阶段 3：清理被替换的旧对象（尽力而为）
  await deleteObjects(c.env, replaced);

  await audit(c.env, ip, {
    actorId: user.id,
    action: "site.upload",
    target: site.id,
    result: "ok",
  });

  return c.json({
    siteUrl: siteUrl(c.env, site.id),
    uploaded: staged.map((s) => ({ path: s.path, size: s.size, contentType: s.contentType })),
  }, 201);
});
