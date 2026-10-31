/// 运行时环境绑定。敏感值只来自 Secret / .dev.vars，绝不写死在代码中。
export interface Env {
  DB: D1Database;
  KV: KVNamespace;
  SITES_BUCKET: R2Bucket;
  ASSETS: Fetcher;

  APP_ORIGIN: string;
  SITES_ROOT_DOMAIN: string;
  SITES_SCHEME: string;

  ADMIN_EMAILS: string;
  ADMIN_USER_IDS: string;

  SESSION_TTL_SECONDS: string;
  PBKDF2_ITERATIONS: string;
  CAPTCHA_TTL_SECONDS: string;
  CAPTCHA_MAX_ATTEMPTS: string;
  CAPTCHA_PROVIDER: string;
  MAIL_MODE?: string;

  MAX_FILE_BYTES: string;
  MAX_UPLOAD_BYTES: string;
  MAX_SITE_BYTES: string;
  MAX_SITE_FILES: string;

  // Secrets
  CAPTCHA_SECRET: string;
  IP_HASH_SECRET: string;
  SESSION_SECRET: string;
  BOOTSTRAP_TOKEN?: string;
  MAIL_WEBHOOK_URL?: string;
  TURNSTILE_SECRET?: string;
}

export interface Limits {
  maxFileBytes: number;
  maxUploadBytes: number;
  maxSiteBytes: number;
  maxSiteFiles: number;
  sessionTtlSeconds: number;
  pbkdf2Iterations: number;
  captchaTtlSeconds: number;
  captchaMaxAttempts: number;
}

export function readLimits(env: Env): Limits {
  const num = (v: string | undefined, fallback: number): number => {
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? n : fallback;
  };
  return {
    maxFileBytes: num(env.MAX_FILE_BYTES, 5 * 1024 * 1024),
    maxUploadBytes: num(env.MAX_UPLOAD_BYTES, 20 * 1024 * 1024),
    maxSiteBytes: num(env.MAX_SITE_BYTES, 100 * 1024 * 1024),
    maxSiteFiles: num(env.MAX_SITE_FILES, 500),
    sessionTtlSeconds: num(env.SESSION_TTL_SECONDS, 86400),
    // 不允许被环境变量降到过低值
    pbkdf2Iterations: Math.max(num(env.PBKDF2_ITERATIONS, 210000), 100000),
    captchaTtlSeconds: num(env.CAPTCHA_TTL_SECONDS, 300),
    captchaMaxAttempts: num(env.CAPTCHA_MAX_ATTEMPTS, 3),
  };
}
