/// Worker 环境绑定。
/// - 非机密配置：见 config/app.config.ts（域名、限额、SMTP、安全策略等）
/// - 超级用户：wrangler.toml [vars] 中的 ADMIN_EMAILS / ADMIN_USER_IDS（规格要求，见 README）
/// - 机密：只通过 Secret / .dev.vars 注入，绝不写死
export interface Env {
  // 绑定
  DB: D1Database;
  KV: KVNamespace;
  /** 用户站点文件的存储（独立 KV namespace，与限速/验证码数据隔离） */
  FILES_KV: KVNamespace;
  ASSETS: Fetcher;

  // 超级用户（非机密，但由部署者控制）
  ADMIN_EMAILS?: string;
  ADMIN_USER_IDS?: string;

  // 机密
  CAPTCHA_SECRET: string;
  IP_HASH_SECRET: string;
  BOOTSTRAP_TOKEN?: string;
  SMTP_USERNAME?: string;
  SMTP_PASSWORD?: string;
  TURNSTILE_SECRET?: string;
}

export { readLimits } from "./config";
