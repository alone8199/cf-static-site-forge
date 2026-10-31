/// 一次性管理员初始化（无邮件服务时使用）。
///
/// 信任根：持有 BOOTSTRAP_TOKEN（Cloudflare Secret）的运维人员。
/// 含义：只有持有该 Secret 的人，才能把某个已注册账号的邮箱标记为已验证。
/// 即便如此，超级用户身份仍需：该邮箱在 ADMIN_EMAILS 中（环境变量）。
///
/// 明确说明：
///   - 不能仅凭"注册了一个在 ADMIN_EMAILS 里的未验证邮箱"获得管理员权限；
///     未验证时 resolveRole() 恒为非管理员。
///   - 本接口只能使用一次：成功后在 KV 写入 bootstrap:consumed 标记，之后永久拒绝。
///   - 使用后应立即从 Secret 中删除 BOOTSTRAP_TOKEN（README 有步骤）。
import { Hono } from "hono";
import { z } from "zod";
import type { AppEnv } from "../middleware/auth";
import { clientIp } from "../middleware/auth";
import { readJson } from "../lib/http";
import { err, AppError } from "../lib/errors";
import { EmailSchema, parseOrThrow } from "../lib/validate";
import { timingSafeEqual, sha256Hex } from "../lib/crypto";
import { consumeRate, RULES } from "../lib/ratelimit";
import { audit } from "../lib/audit";
import { nowSec } from "../auth/session";
import { findUserByEmail, markEmailVerified } from "../db/users";
import { resolveRole } from "../auth/roles";
import { getAdminEmails } from "../config";

export const bootstrapRoutes = new Hono<AppEnv>();

const CONSUMED_KEY = "bootstrap:consumed";

const BodySchema = z.object({
  token: z.string().min(32).max(256),
  email: EmailSchema,
});

bootstrapRoutes.post("/", async (c) => {
  const ip = clientIp(c);
  await consumeRate(c.env, RULES.verifyEmail, `bootstrap:${ip ?? "unknown"}`);

  const configured = c.env.BOOTSTRAP_TOKEN;
  if (!configured || configured.length < 32) {
    throw err.notFound();
  }
  if ((await c.env.KV.get(CONSUMED_KEY)) !== null) {
    throw err.conflict("bootstrap_used", "初始化令牌已使用");
  }

  const input = parseOrThrow(BodySchema, await readJson(c));
  if (!timingSafeEqual(input.token, configured)) {
    await audit(c.env, ip, { action: "bootstrap", result: "denied" });
    throw err.forbidden("令牌无效");
  }

  // 只允许为环境变量中的超级用户邮箱执行初始化，其他邮箱无意义
  if (!getAdminEmails(c.env).includes(input.email)) {
    await audit(c.env, ip, { action: "bootstrap", target: "not_admin_email", result: "denied" });
    throw err.forbidden("该邮箱不在 ADMIN_EMAILS 中");
  }

  const user = await findUserByEmail(c.env, input.email);
  if (!user) throw new AppError(404, "user_not_found", "请先注册该邮箱账号");

  await markEmailVerified(c.env, user.id, nowSec());
  // 标记为已使用（无过期时间，永久生效）
  await c.env.KV.put(CONSUMED_KEY, await sha256Hex(`${input.email}:${nowSec()}`));

  const role = resolveRole(c.env, { ...user, email_verified: 1 });
  await audit(c.env, ip, { actorId: user.id, action: "bootstrap", result: "ok" });

  return c.json({
    ok: true,
    isSuperAdmin: role.isSuperAdmin,
    message: "邮箱已验证。请立即从 Secret 中删除 BOOTSTRAP_TOKEN。",
  });
});
