/// 超级用户判定。角色每次都重新计算，绝不信任客户端、请求体或数据库中的角色字段。
///
/// 判定规则（任一满足即为超级用户，且账号必须处于 active 且邮箱已验证）：
///   1. email 在环境变量 ADMIN_EMAILS 中（不区分大小写）
///   2. user.id 在环境变量 ADMIN_USER_IDS 中
///
/// 说明：规格允许"ID 白名单"不要求验证，这里更严格：两条路径都要求 email_verified=1，
/// 防止未验证账号通过任一路径获得管理员权限。
import type { Env } from "../env";

export interface RoleSubject {
  id: string;
  email: string;
  email_verified: number | boolean;
  status: string;
}

export interface Role {
  isSuperAdmin: boolean;
  /** 角色来源，便于审计与调试（不包含敏感值） */
  source: "env_email" | "env_user_id" | "none";
}

function parseList(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export function resolveRole(env: Env, user: RoleSubject): Role {
  const verified = user.email_verified === 1 || user.email_verified === true;
  if (!verified || user.status !== "active") {
    return { isSuperAdmin: false, source: "none" };
  }

  const adminEmails = parseList(env.ADMIN_EMAILS).map((e) => e.toLowerCase());
  if (adminEmails.includes(user.email.toLowerCase())) {
    return { isSuperAdmin: true, source: "env_email" };
  }

  const adminIds = parseList(env.ADMIN_USER_IDS);
  if (adminIds.includes(user.id)) {
    return { isSuperAdmin: true, source: "env_user_id" };
  }

  return { isSuperAdmin: false, source: "none" };
}

/// 判断某账号是否是"受保护的超级用户"（UI 层不可删除、不可禁用）
export function isProtectedAdmin(env: Env, user: { id: string; email: string }): boolean {
  const adminEmails = parseList(env.ADMIN_EMAILS).map((e) => e.toLowerCase());
  return (
    adminEmails.includes(user.email.toLowerCase()) ||
    parseList(env.ADMIN_USER_IDS).includes(user.id)
  );
}
