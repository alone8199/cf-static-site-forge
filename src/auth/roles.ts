/// 超级用户判定。角色每次都重新计算，绝不信任客户端、请求体或数据库中的角色字段。
///
/// 判定规则（两条路径都要求：账号 active 且邮箱已验证）：
///   1. 邮箱在环境变量 ADMIN_EMAILS 中（不区分大小写）
///   2. 用户 ID 在环境变量 ADMIN_USER_IDS 中
///
/// 说明：规格允许“ID 白名单”不要求验证；本实现更严格，防止未验证账号获得管理员权限。
import type { Env } from "../env";
import { getAdminEmails, getAdminIds } from "../config";

export interface RoleSubject {
  id: string;
  email: string;
  email_verified: number | boolean;
  status: string;
}

export interface Role {
  isSuperAdmin: boolean;
  source: "env_email" | "env_user_id" | "none";
}

export function resolveRole(env: Env, user: RoleSubject): Role {
  const verified = user.email_verified === 1 || user.email_verified === true;
  if (!verified || user.status !== "active") {
    return { isSuperAdmin: false, source: "none" };
  }
  if (getAdminEmails(env).includes(user.email.toLowerCase())) {
    return { isSuperAdmin: true, source: "env_email" };
  }
  if (getAdminIds(env).includes(user.id)) {
    return { isSuperAdmin: true, source: "env_user_id" };
  }
  return { isSuperAdmin: false, source: "none" };
}

/// 环境变量指定的超级用户（不论验证状态）。UI 与 API 中不可禁用、不可删除。
export function isProtectedAdmin(env: Env, user: { id: string; email: string }): boolean {
  return (
    getAdminEmails(env).includes(user.email.toLowerCase()) ||
    getAdminIds(env).includes(user.id)
  );
}
