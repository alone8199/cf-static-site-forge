/// 管理员 API。所有接口由服务端 requireSuperAdmin 鉴权，前端隐藏不构成授权。
/// 环境变量指定的超级用户不可被禁用或删除（UI 与 API 均拒绝）。
import { Hono, type Context } from "hono";
import { z } from "zod";
import type { AppEnv } from "../middleware/auth";
import { clientIp, requireSuperAdmin } from "../middleware/auth";
import { err } from "../lib/errors";
import { IdParamSchema, parseOrThrow } from "../lib/validate";
import { consumeRate, RULES } from "../lib/ratelimit";
import { audit } from "../lib/audit";
import { nowSec } from "../auth/session";
import { isProtectedAdmin } from "../auth/roles";
import { findUserById, listUsers, setUserStatus } from "../db/users";
import { softDeleteSite, getSite } from "../sites/store";

export const adminRoutes = new Hono<AppEnv>();

adminRoutes.use("*", requireSuperAdmin());

const PageSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).max(100000).default(0),
});

function pageParams(c: Context<AppEnv>) {
  return parseOrThrow(PageSchema, {
    limit: c.req.query("limit"),
    offset: c.req.query("offset"),
  });
}

// ---------- 用户 ----------
adminRoutes.get("/users", async (c) => {
  const { limit, offset } = pageParams(c);
  const rows = await listUsers(c.env, limit, offset);
  return c.json({
    users: rows.map((r) => ({
      id: r.id,
      email: r.email,
      emailVerified: r.email_verified === 1,
      status: r.status,
      createdAt: r.created_at,
      siteCount: r.site_count,
      // 环境变量超级用户标记，供前端展示（仅展示用途，不作为授权依据）
      protected: isProtectedAdmin(c.env, { id: r.id, email: r.email }),
    })),
  });
});

async function setStatus(c: Context<AppEnv>, status: "active" | "disabled") {
  const ip = clientIp(c);
  const actor = c.get("user");
  await consumeRate(c.env, RULES.adminWrite, actor.id);
  const userId = parseOrThrow(IdParamSchema, c.req.param("userId"));
  const target = await findUserById(c.env, userId);
  if (!target) throw err.notFound();
  if (target.id === actor.id && status === "disabled") {
    throw err.conflict("self_disable", "不能禁用自己");
  }
  if (status === "disabled" && isProtectedAdmin(c.env, target)) {
    await audit(c.env, ip, { actorId: actor.id, action: "user.disable", target: target.id, result: "denied" });
    throw err.forbidden("环境变量指定的超级用户不可禁用");
  }
  await setUserStatus(c.env, target.id, status, nowSec());
  if (status === "disabled") {
    // 禁用后立即吊销其所有会话
    await c.env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?1`).bind(target.id).run();
  }
  await audit(c.env, ip, {
    actorId: actor.id,
    action: status === "disabled" ? "user.disable" : "user.enable",
    target: target.id,
    result: "ok",
  });
  return c.json({ ok: true, status });
}

adminRoutes.post("/users/:userId/disable", (c) => setStatus(c, "disabled"));
adminRoutes.post("/users/:userId/enable", (c) => setStatus(c, "active"));

// ---------- 站点 ----------
adminRoutes.get("/sites", async (c) => {
  const { limit, offset } = pageParams(c);
  const res = await c.env.DB.prepare(
    `SELECT s.id, s.name, s.status, s.total_bytes, s.file_count, s.created_at,
            u.email AS owner_email, u.id AS owner_id
       FROM sites s JOIN users u ON u.id = s.owner_id
      WHERE s.status != 'deleted'
      ORDER BY s.created_at DESC
      LIMIT ?1 OFFSET ?2`,
  )
    .bind(limit, offset)
    .all<{
      id: string;
      name: string;
      status: string;
      total_bytes: number;
      file_count: number;
      created_at: number;
      owner_email: string;
      owner_id: string;
    }>();
  return c.json({
    sites: (res.results ?? []).map((s) => ({
      id: s.id,
      name: s.name,
      status: s.status,
      totalBytes: s.total_bytes,
      fileCount: s.file_count,
      createdAt: s.created_at,
      ownerEmail: s.owner_email,
      ownerId: s.owner_id,
    })),
  });
});

adminRoutes.delete("/sites/:siteId", async (c) => {
  const actor = c.get("user");
  await consumeRate(c.env, RULES.adminWrite, actor.id);
  const siteId = parseOrThrow(IdParamSchema, c.req.param("siteId"));
  const site = await getSite(c.env, siteId);
  if (!site) throw err.notFound();
  await softDeleteSite(c.env, site.id, nowSec());
  await audit(c.env, clientIp(c), {
    actorId: actor.id,
    action: "admin.site.delete",
    target: site.id,
    result: "ok",
  });
  return c.json({ ok: true });
});

// ---------- 审计日志 ----------
adminRoutes.get("/audit", async (c) => {
  const { limit, offset } = pageParams(c);
  const res = await c.env.DB.prepare(
    `SELECT id, actor_id, action, target, ip_hash, result, created_at
       FROM audit_logs ORDER BY id DESC LIMIT ?1 OFFSET ?2`,
  )
    .bind(limit, offset)
    .all<{
      id: number;
      actor_id: string | null;
      action: string;
      target: string | null;
      ip_hash: string | null;
      result: string;
      created_at: number;
    }>();
  return c.json({
    logs: (res.results ?? []).map((r) => ({
      id: r.id,
      actorId: r.actor_id,
      action: r.action,
      target: r.target,
      ipHash: r.ip_hash,
      result: r.result,
      createdAt: r.created_at,
    })),
  });
});
