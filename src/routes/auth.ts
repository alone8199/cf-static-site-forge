/// 用户系统路由：注册、登录、退出、当前用户、改密、邮箱验证。
import { Hono } from "hono";
import { z } from "zod";
import type { AppEnv } from "../middleware/auth";
import { clientIp, requireAuth, resolveCurrentUser } from "../middleware/auth";
import { readJson } from "../lib/http";
import { err, AppError } from "../lib/errors";
import { EmailSchema, PasswordSchema, CaptchaIdSchema, CaptchaAnswerSchema, parseOrThrow } from "../lib/validate";
import { hashPassword, verifyPassword, randomId, randomToken, sha256Hex } from "../lib/crypto";
import { consumeRate, failureDelayMs, sleep, RULES } from "../lib/ratelimit";
import { audit } from "../lib/audit";
import { getCaptchaProvider } from "../lib/turnstile";
import { readLimits } from "../env";
import { createSession, destroySession, sessionCookie, clearSessionCookie, revokeAllSessions, nowSec, readSessionToken } from "../auth/session";
import { findUserByEmail, findUserById, insertUser, markEmailVerified, updatePassword, recordLoginFailure, recordLoginSuccess, type UserRow } from "../db/users";
import { resolveRole } from "../auth/roles";
import { deliverVerification } from "../auth/mail";

export const authRoutes = new Hono<AppEnv>();

const VERIFY_TTL_SECONDS = 24 * 3600;
const LOCK_THRESHOLD = 5;
const LOCK_SECONDS = 900;

const captchaBody = {
  captchaId: CaptchaIdSchema,
  captchaAnswer: CaptchaAnswerSchema,
};

const RegisterSchema = z.object({ email: EmailSchema, password: PasswordSchema, ...captchaBody });
const LoginSchema = z.object({
  email: EmailSchema,
  password: z.string().min(1).max(128),
  ...captchaBody,
});
const ChangePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(128),
  newPassword: PasswordSchema,
});
const VerifyEmailSchema = z.object({ token: z.string().regex(/^[A-Za-z0-9_-]{20,128}$/) });
const ResendSchema = z.object({ email: EmailSchema, ...captchaBody });

function publicUser(row: { id: string; email: string; email_verified: number; status: string }, env: AppEnv["Bindings"]) {
  return {
    id: row.id,
    email: row.email,
    emailVerified: row.email_verified === 1,
    status: row.status,
    isSuperAdmin: resolveRole(env, row).isSuperAdmin,
  };
}

// ---------- 注册 ----------
authRoutes.post("/register", async (c) => {
  const ip = clientIp(c);
  await consumeRate(c.env, RULES.register, ip ?? "unknown");
  const input = parseOrThrow(RegisterSchema, await readJson(c));
  await getCaptchaProvider(c.env).verify(c.env, ip, input);

  const existing = await findUserByEmail(c.env, input.email);
  if (existing) {
    await audit(c.env, ip, { action: "register", target: "duplicate_email", result: "denied" });
    throw err.conflict("email_taken", "该邮箱已注册");
  }

  const limits = readLimits(c.env);
  const now = nowSec();
  const id = randomId(16);
  const pw = await hashPassword(input.password, limits.pbkdf2Iterations);
  await insertUser(c.env, { id, email: input.email, password: pw, now });

  const token = randomToken(32);
  await c.env.DB.prepare(
    `INSERT INTO email_verifications (token_hash, user_id, expires_at, used_at, created_at)
     VALUES (?1, ?2, ?3, NULL, ?4)`,
  )
    .bind(await sha256Hex(token), id, now + VERIFY_TTL_SECONDS, now)
    .run();
  const delivery = await deliverVerification(c.env, input.email, token);

  await audit(c.env, ip, { actorId: id, action: "register", result: "ok" });
  return c.json(
    {
      ok: true,
      message: "注册成功，请完成邮箱验证后再登录",
      // 仅 MAIL_MODE=dev 时返回，生产环境为 undefined
      ...(delivery.devToken ? { devVerificationToken: delivery.devToken } : {}),
    },
    201,
  );
});

// ---------- 登录 ----------
authRoutes.post("/login", async (c) => {
  const ip = clientIp(c);
  await consumeRate(c.env, RULES.login, ip ?? "unknown");
  const input = parseOrThrow(LoginSchema, await readJson(c));
  await getCaptchaProvider(c.env).verify(c.env, ip, input);
  await consumeRate(c.env, RULES.loginAccount, input.email);

  const limits = readLimits(c.env);
  const user = await findUserByEmail(c.env, input.email);
  const now = nowSec();
  const genericFail = () => new AppError(401, "invalid_credentials", "邮箱或密码错误");

  // 即使用户不存在也执行一次哈希，缩小时序差异
  if (!user) {
    await hashPassword(input.password, limits.pbkdf2Iterations);
    await sleep(failureDelayMs(3));
    await audit(c.env, ip, { action: "login", target: "unknown_user", result: "denied" });
    throw genericFail();
  }

  if (user.locked_until && user.locked_until > now) {
    await audit(c.env, ip, { actorId: user.id, action: "login", target: "locked", result: "denied" });
    throw err.rateLimited(user.locked_until - now);
  }

  const ok = await verifyPassword(input.password, {
    hash: user.password_hash,
    salt: user.password_salt,
    iterations: user.password_iter,
  });

  if (!ok) {
    const failures = user.failed_logins + 1;
    const lockedUntil = failures >= LOCK_THRESHOLD ? now + LOCK_SECONDS : null;
    await recordLoginFailure(c.env, user.id, failures, lockedUntil, now);
    await sleep(failureDelayMs(failures));
    await audit(c.env, ip, { actorId: user.id, action: "login", result: "denied" });
    throw genericFail();
  }

  if (user.status !== "active") {
    await audit(c.env, ip, { actorId: user.id, action: "login", target: "disabled", result: "denied" });
    throw new AppError(403, "account_disabled", "账号已被禁用");
  }
  if (user.email_verified !== 1) {
    throw new AppError(403, "email_unverified", "请先完成邮箱验证");
  }

  await recordLoginSuccess(c.env, user.id, now);
  const session = await createSession(c.env, user.id, ip);
  await audit(c.env, ip, { actorId: user.id, action: "login", result: "ok" });

  c.header("Set-Cookie", sessionCookie(session.token, limits.sessionTtlSeconds));
  return c.json({
    user: publicUser(user, c.env),
    csrfToken: session.csrfToken,
    expiresAt: session.expiresAt,
  });
});

// ---------- 退出 ----------
authRoutes.post("/logout", async (c) => {
  // 退出仅需要有效 Cookie；为避免 CSRF 只清除自身会话，SameSite=Strict 已足够
  const cookie = c.req.header("cookie") ?? null;
  const current = await resolveCurrentUser(c.env, cookie);
  const token = readSessionToken(cookie);
  if (token) await destroySession(c.env, token);
  if (current) await audit(c.env, clientIp(c), { actorId: current.user.id, action: "logout", result: "ok" });
  c.header("Set-Cookie", clearSessionCookie());
  return c.json({ ok: true });
});

// ---------- 当前用户 ----------
authRoutes.get("/me", async (c) => {
  const current = await resolveCurrentUser(c.env, c.req.header("cookie") ?? null);
  if (!current) throw err.unauthorized();
  const row = await findUserById(c.env, current.user.id);
  if (!row) throw err.unauthorized();
  return c.json({
    user: publicUser(row, c.env),
    csrfToken: current.csrfToken,
  });
});

// ---------- 修改密码 ----------
authRoutes.post("/change-password", requireAuth(), async (c) => {
  const user = c.get("user");
  await consumeRate(c.env, RULES.changePassword, user.id);
  const input = parseOrThrow(ChangePasswordSchema, await readJson(c));
  const row = (await findUserById(c.env, user.id)) as UserRow;

  const ok = await verifyPassword(input.currentPassword, {
    hash: row.password_hash,
    salt: row.password_salt,
    iterations: row.password_iter,
  });
  if (!ok) {
    await audit(c.env, clientIp(c), { actorId: user.id, action: "change_password", result: "denied" });
    throw new AppError(401, "invalid_credentials", "当前密码错误");
  }
  if (input.newPassword === input.currentPassword) {
    throw err.badRequest("same_password", "新密码不能与旧密码相同");
  }

  const limits = readLimits(c.env);
  const pw = await hashPassword(input.newPassword, limits.pbkdf2Iterations);
  await updatePassword(c.env, user.id, pw, nowSec());
  // 修改密码后吊销所有会话，并为当前请求重新签发
  await revokeAllSessions(c.env, user.id);
  const session = await createSession(c.env, user.id, clientIp(c));
  await audit(c.env, clientIp(c), { actorId: user.id, action: "change_password", result: "ok" });

  c.header("Set-Cookie", sessionCookie(session.token, limits.sessionTtlSeconds));
  return c.json({ ok: true, csrfToken: session.csrfToken });
});

// ---------- 邮箱验证 ----------
authRoutes.post("/verify-email", async (c) => {
  const ip = clientIp(c);
  await consumeRate(c.env, RULES.verifyEmail, ip ?? "unknown");
  const input = parseOrThrow(VerifyEmailSchema, await readJson(c));
  const tokenHash = await sha256Hex(input.token);
  const now = nowSec();

  const row = await c.env.DB.prepare(
    `SELECT user_id, expires_at, used_at FROM email_verifications WHERE token_hash = ?1`,
  )
    .bind(tokenHash)
    .first<{ user_id: string; expires_at: number; used_at: number | null }>();

  if (!row || row.used_at !== null || row.expires_at <= now) {
    throw new AppError(400, "invalid_token", "验证链接无效或已过期");
  }
  await c.env.DB.prepare(`UPDATE email_verifications SET used_at = ?2 WHERE token_hash = ?1`)
    .bind(tokenHash, now)
    .run();
  await markEmailVerified(c.env, row.user_id, now);
  await audit(c.env, ip, { actorId: row.user_id, action: "verify_email", result: "ok" });
  return c.json({ ok: true, message: "邮箱验证成功" });
});

// ---------- 重新发送验证邮件（不泄露邮箱是否存在）----------
authRoutes.post("/resend-verification", async (c) => {
  const ip = clientIp(c);
  await consumeRate(c.env, RULES.register, `resend:${ip ?? "unknown"}`);
  const input = parseOrThrow(ResendSchema, await readJson(c));
  await getCaptchaProvider(c.env).verify(c.env, ip, input);

  const user = await findUserByEmail(c.env, input.email);
  if (user && user.email_verified !== 1) {
    const token = randomToken(32);
    const now = nowSec();
    await c.env.DB.prepare(
      `INSERT INTO email_verifications (token_hash, user_id, expires_at, used_at, created_at)
       VALUES (?1, ?2, ?3, NULL, ?4)`,
    )
      .bind(await sha256Hex(token), user.id, now + VERIFY_TTL_SECONDS, now)
      .run();
    await deliverVerification(c.env, user.email, token);
  }
  // 无论邮箱是否存在，响应一致
  return c.json({ ok: true, message: "若该邮箱待验证，验证邮件已发送" });
});
