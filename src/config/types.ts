/// 配置类型定义。实际值在 config/app.config.ts 中，修改那里即可。

export type MailMode = "smtp" | "dev" | "none";
export type SmtpTls = "implicit" | "starttls" | "none";
export type CaptchaProviderName = "image" | "turnstile";

export interface SignatureRule {
  name: string;
  bytes: number[];
}

export interface AppConfig {
  app: { origin: string; name: string };
  sites: { rootDomain: string; scheme: "https" | "http"; maxPerUser: number };
  session: { ttlSeconds: number };
  password: {
    minLength: number;
    maxLength: number;
    requireLower: boolean;
    requireUpper: boolean;
    requireDigit: boolean;
    pbkdf2Iterations: number;
    pbkdf2MinIterations: number;
  };
  auth: {
    lockThreshold: number;
    lockSeconds: number;
    failureDelayMaxMs: number;
    emailVerifyTtlSeconds: number;
  };
  captcha: {
    provider: CaptchaProviderName;
    ttlSeconds: number;
    maxAttempts: number;
    minLength: number;
    maxLength: number;
    alphabet: string;
  };
  upload: {
    maxFileBytes: number;
    maxUploadBytes: number;
    maxSiteBytes: number;
    maxSiteFiles: number;
    maxFilesPerRequest: number;
    maxPathLength: number;
    maxPathDepth: number;
    maxSegmentLength: number;
  };
  security: {
    allowedExtensions: Record<string, string>;
    blockedExtensions: string[];
    blockedFilenames: string[];
    blockedDirectories: string[];
    content: {
      enabled: boolean;
      forbiddenSignatures: SignatureRule[];
      forbiddenMarkers: string[];
      requireUtf8Text: boolean;
      verifyBinaryMagic: boolean;
      svg: {
        rejectScripts: boolean;
        rejectEventHandlers: boolean;
        rejectExternalRefs: boolean;
        rejectEntities: boolean;
        rejectForeignObject: boolean;
      };
      htmlRejectTags: string[];
    };
  };
  siteResponse: {
    contentSecurityPolicy: string;
    htmlCacheControl: string;
    assetCacheControl: string;
    permissionsPolicy: string;
  };
  rateLimits: Record<string, { limit: number; windowSeconds: number }>;
  mail: {
    mode: MailMode;
    from: string;
    fromName: string;
    subject: string;
    smtp: {
      host: string;
      port: number;
      tls: SmtpTls;
      timeoutMs: number;
      requireAuth: boolean;
    };
  };
  audit: { retentionDays: number };
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
