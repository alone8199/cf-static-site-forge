/// 用户表访问。全部使用参数化查询。
import type { Env } from "../env";
import type { PasswordRecord } from "../lib/crypto";

export interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  password_salt: string;
  password_iter: number;
  email_verified: number;
  status: string;
  failed_logins: number;
  locked_until: number | null;
  created_at: number;
  updated_at: number;
}

export async function findUserByEmail(env: Env, email: string): Promise<UserRow | null> {
  return env.DB.prepare(`SELECT * FROM users WHERE email = ?1`)
    .bind(email)
    .first<UserRow>();
}

export async function findUserById(env: Env, id: string): Promise<UserRow | null> {
  return env.DB.prepare(`SELECT * FROM users WHERE id = ?1`).bind(id).first<UserRow>();
}

export async function insertUser(
  env: Env,
  args: { id: string; email: string; password: PasswordRecord; now: number },
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO users
       (id, email, password_hash, password_salt, password_iter, email_verified, status,
        failed_logins, locked_until, created_at, updated_at)
     VALUES (?1, ?2, ?3, ?4, ?5, 0, 'active', 0, NULL, ?6, ?6)`,
  )
    .bind(
      args.id,
      args.email,
      args.password.hash,
      args.password.salt,
      args.password.iterations,
      args.now,
    )
    .run();
}

export async function markEmailVerified(env: Env, userId: string, now: number): Promise<void> {
  await env.DB.prepare(
    `UPDATE users SET email_verified = 1, updated_at = ?2 WHERE id = ?1`,
  )
    .bind(userId, now)
    .run();
}

export async function updatePassword(
  env: Env,
  userId: string,
  password: PasswordRecord,
  now: number,
): Promise<void> {
  await env.DB.prepare(
    `UPDATE users
        SET password_hash = ?2, password_salt = ?3, password_iter = ?4,
            failed_logins = 0, locked_until = NULL, updated_at = ?5
      WHERE id = ?1`,
  )
    .bind(userId, password.hash, password.salt, password.iterations, now)
    .run();
}

export async function recordLoginFailure(
  env: Env,
  userId: string,
  failedLogins: number,
  lockedUntil: number | null,
  now: number,
): Promise<void> {
  await env.DB.prepare(
    `UPDATE users SET failed_logins = ?2, locked_until = ?3, updated_at = ?4 WHERE id = ?1`,
  )
    .bind(userId, failedLogins, lockedUntil, now)
    .run();
}

export async function recordLoginSuccess(env: Env, userId: string, now: number): Promise<void> {
  await env.DB.prepare(
    `UPDATE users SET failed_logins = 0, locked_until = NULL, updated_at = ?2 WHERE id = ?1`,
  )
    .bind(userId, now)
    .run();
}

export async function setUserStatus(
  env: Env,
  userId: string,
  status: "active" | "disabled",
  now: number,
): Promise<void> {
  await env.DB.prepare(`UPDATE users SET status = ?2, updated_at = ?3 WHERE id = ?1`)
    .bind(userId, status, now)
    .run();
}

export interface UserListRow {
  id: string;
  email: string;
  email_verified: number;
  status: string;
  created_at: number;
  site_count: number;
}

export async function listUsers(env: Env, limit: number, offset: number): Promise<UserListRow[]> {
  const res = await env.DB.prepare(
    `SELECT u.id, u.email, u.email_verified, u.status, u.created_at,
            (SELECT COUNT(*) FROM sites s WHERE s.owner_id = u.id AND s.status != 'deleted') AS site_count
       FROM users u
      ORDER BY u.created_at DESC
      LIMIT ?1 OFFSET ?2`,
  )
    .bind(limit, offset)
    .all<UserListRow>();
  return res.results ?? [];
}
