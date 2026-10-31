/// 鉴权、CSRF 与管理员中间件。所有判断均在服务端完成，前端隐藏不构成授权。
import type { Context, Next } from "hono";
import type { Env } from "../env";
import { loadSession, readSessionToken } from "../auth/session";
import { findUserById, type UserRow } from "../db/users";
import { resolveRole, type Role } from "../auth/roles";
import { timingSafeEqual } from "../lib/crypto";
import { err } from "../lib/errors";
import { getConfig } from "../config";

export interface AuthUser {
  id: string;
  email: string;
  emailVerified: boolean;
  status: string;
  role: Role;
}

export type AppVariables = {
  user: AuthUser;
  csrfToken: string;
  clientIp: string | null;
};

export type AppEnv = { Bindings: Env; Variables: AppVariables };

export function clientIp(c: Context): string | null {
  return c.req.header("cf-connecting-ip") ?? null;
}

/// Origin 校验：若请求带 Origin，必须等于主应用 Origin（来自配置）。
export function originAllowed(origin: string | undefined | null): boolean {
  if (origin === undefined || origin === null) return true; // 非浏览器客户端由 CSRF token 约束
  return origin === getConfig().app.origin;
}

/// 解析当前用户（不强制登录）。返回 null 表示匿名。
export async function resolveCurrentUser(
  env: Env,
  cookieHeader: string | null,
): Promise<{ user: AuthUser; csrfToken: string } | null> {
  const token = readSessionToken(cookieHeader);
  if (!token) return null;

  const session = await loadSession(env, token);
  if (!session) return null;

  const row: UserRow | null = await findUserById(env, session.userId);
  if (!row || row.status !== "active") return null;

  return {
    user: {
      id: row.id,
      email: row.email,
      emailVerified: row.email_verified === 1,
      status: row.status,
      // 每次请求重新计算角色，环境变量变更后立即对新请求生效
      role: resolveRole(env, row),
    },
    csrfToken: session.csrfToken,
  };
}

/// 要求已登录；状态变更请求校验 Origin 与 X-CSRF-Token。
export function requireAuth() {
  return async (c: Context<AppEnv>, next: Next) => {
    if (!originAllowed(c.req.header("origin"))) {
      throw err.forbidden("请求来源不被允许");
    }
    const current = await resolveCurrentUser(c.env, c.req.header("cookie") ?? null);
    if (!current) throw err.unauthorized();

    if (!["GET", "HEAD", "OPTIONS"].includes(c.req.method)) {
      const header = c.req.header("x-csrf-token") ?? "";
      if (!header || !timingSafeEqual(header, current.csrfToken)) {
        throw err.forbidden("CSRF 校验失败");
      }
    }

    c.set("user", current.user);
    c.set("csrfToken", current.csrfToken);
    c.set("clientIp", clientIp(c));
    await next();
  };
}

/// 要求超级用户。角色来自服务端实时计算。
export function requireSuperAdmin() {
  const base = requireAuth();
  return async (c: Context<AppEnv>, next: Next) => {
    await base(c, async () => {
      if (!c.get("user").role.isSuperAdmin) throw err.forbidden("需要管理员权限");
      await next();
    });
  };
}
