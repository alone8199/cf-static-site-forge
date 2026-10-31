/// 配置访问层。非机密配置来自 config/app.config.ts；机密与超级用户列表来自环境变量。
import appConfig from "../../config/app.config";
import type { AppConfig, Limits } from "./types";
import { AppError } from "../lib/errors";

export type { AppConfig, Limits } from "./types";

let validated = false;

/// 启动期（首次访问时）校验配置，发现明显危险的设置立即失败，而不是静默降级。
export function getConfig(): AppConfig {
  if (!validated) {
    validateConfig(appConfig);
    validated = true;
  }
  return appConfig;
}

export function validateConfig(c: AppConfig): void {
  const problems: string[] = [];
  const origin = new URL(c.app.origin);
  if (origin.protocol !== "https:" && origin.hostname !== "localhost") {
    problems.push("app.origin 必须是 https");
  }
  if (c.sites.scheme !== "https" && c.sites.rootDomain !== "localhost") {
    problems.push("sites.scheme 生产必须为 https");
  }
  if (c.sites.rootDomain === origin.hostname || origin.hostname.endsWith("." + c.sites.rootDomain)) {
    problems.push("sites.rootDomain 不能与主应用域名相同或互为父子，否则破坏站点隔离");
  }
  if (c.password.pbkdf2Iterations < c.password.pbkdf2MinIterations) {
    problems.push("password.pbkdf2Iterations 低于 pbkdf2MinIterations");
  }
  if (c.password.minLength < 8) problems.push("password.minLength 不得小于 8");
  if (c.captcha.alphabet.length < 20) problems.push("captcha.alphabet 过短");
  if (c.captcha.minLength < 4 || c.captcha.maxLength > 6 || c.captcha.minLength > c.captcha.maxLength) {
    problems.push("captcha 长度必须在 4–6 之间");
  }
  // Workers KV 单个值上限 25 MiB
  if (c.upload.maxFileBytes > 25 * 1024 * 1024) {
    problems.push("upload.maxFileBytes 不能超过 25 MiB（Workers KV 单值上限）");
  }
  if (c.upload.maxFileBytes > c.upload.maxUploadBytes) {
    problems.push("upload.maxFileBytes 不能大于 maxUploadBytes");
  }
  if (c.upload.maxUploadBytes > c.upload.maxSiteBytes) {
    problems.push("upload.maxUploadBytes 不能大于 maxSiteBytes");
  }
  for (const ext of Object.keys(c.security.allowedExtensions)) {
    if (c.security.blockedExtensions.includes(ext)) {
      problems.push(`扩展名 .${ext} 同时出现在允许与黑名单中`);
    }
  }
  // 明文 SMTP 只允许指向本机（开发用），且发送端会拒绝在明文上传输凭据
  if (c.mail.mode === "smtp" && c.mail.smtp.tls === "none") {
    const h = c.mail.smtp.host;
    if (h !== "localhost" && h !== "127.0.0.1") {
      problems.push("mail.smtp.tls=none 仅允许 localhost（生产必须使用 implicit 或 starttls）");
    }
  }
  if (problems.length > 0) {
    // 只输出配置问题，不输出任何值
    throw new AppError(500, "invalid_config", `配置错误：${problems.join("；")}`);
  }
}

export function readLimits(_env?: unknown): Limits {
  const c = getConfig();
  return {
    maxFileBytes: c.upload.maxFileBytes,
    maxUploadBytes: c.upload.maxUploadBytes,
    maxSiteBytes: c.upload.maxSiteBytes,
    maxSiteFiles: c.upload.maxSiteFiles,
    sessionTtlSeconds: c.session.ttlSeconds,
    pbkdf2Iterations: Math.max(c.password.pbkdf2Iterations, c.password.pbkdf2MinIterations),
    captchaTtlSeconds: c.captcha.ttlSeconds,
    captchaMaxAttempts: c.captcha.maxAttempts,
  };
}

function parseList(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);
}

/// 超级用户邮箱（小写）。来自环境变量 ADMIN_EMAILS。
export function getAdminEmails(env: { ADMIN_EMAILS?: string }): string[] {
  return parseList(env.ADMIN_EMAILS);
}

/// 超级用户 ID（区分大小写，原样保留）。来自环境变量 ADMIN_USER_IDS。
export function getAdminIds(env: { ADMIN_USER_IDS?: string }): string[] {
  return (env.ADMIN_USER_IDS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}
