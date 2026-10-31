/// ============================================================================
/// 应用配置（非机密）。修改这里即可调整域名、限额、邮件、安全策略等。
/// 修改后执行 `npm run deploy` 生效（配置在构建时打包进 Worker）。
///
/// 机密不要写在这里，使用 `wrangler secret put` 或本地 .dev.vars：
///   CAPTCHA_SECRET, IP_HASH_SECRET, SESSION_SECRET, BOOTSTRAP_TOKEN,
///   SMTP_USERNAME, SMTP_PASSWORD, TURNSTILE_SECRET
/// 超级用户邮箱/ID 由 wrangler.toml 的 [vars] ADMIN_EMAILS / ADMIN_USER_IDS 控制（规格要求）。
/// ============================================================================

import type { AppConfig } from "../src/config/types";

const config: AppConfig = {
  // ---------- 域名 ----------
  app: {
    origin: "https://app.example.com", // 主应用来源，用于 Origin 校验与邮件链接
    name: "静态建站",
  },
  sites: {
    rootDomain: "sites.example.com", // 用户站点通配符子域根：{siteId}.sites.example.com
    scheme: "https",
    maxPerUser: 20,
  },

  // ---------- 会话 ----------
  session: {
    ttlSeconds: 86400,
  },

  // ---------- 密码策略 ----------
  password: {
    minLength: 10,
    maxLength: 128,
    requireLower: true,
    requireUpper: true,
    requireDigit: true,
    pbkdf2Iterations: 210000,
    pbkdf2MinIterations: 100000, // 环境/配置无法把迭代次数降到此值以下
  },

  // ---------- 账号锁定 ----------
  auth: {
    lockThreshold: 5, // 连续失败次数
    lockSeconds: 900,
    failureDelayMaxMs: 2000,
    emailVerifyTtlSeconds: 86400,
  },

  // ---------- 图片验证码 ----------
  captcha: {
    provider: "image", // "image" | "turnstile"
    ttlSeconds: 300,
    maxAttempts: 3,
    minLength: 4,
    maxLength: 6,
    // 排除易混淆字符 0 O 1 I L
    alphabet: "23456789ABCDEFGHJKMNPQRSTUVWXYZ",
  },

  // ---------- 上传限额 ----------
  // 存储后端为 Workers KV：单值上限 25 MiB；每个文件产生 1 次写入，删除/替换也计写入。
  // 免费套餐每天仅 1,000 次写入，请根据用量选择付费套餐。
  upload: {
    maxFileBytes: 5 * 1024 * 1024, // 单文件 5 MiB
    maxUploadBytes: 20 * 1024 * 1024, // 单次请求总量 20 MiB
    maxSiteBytes: 100 * 1024 * 1024, // 站点总容量 100 MiB
    maxSiteFiles: 500,
    maxFilesPerRequest: 50,
    maxPathLength: 256,
    maxPathDepth: 8,
    maxSegmentLength: 128,
  },

  // ---------- 文件安全策略 ----------
  security: {
    /** 允许的扩展名及对应 Content-Type。白名单之外一律拒绝。 */
    allowedExtensions: {
      html: "text/html; charset=utf-8",
      htm: "text/html; charset=utf-8",
      css: "text/css; charset=utf-8",
      js: "text/javascript; charset=utf-8",
      mjs: "text/javascript; charset=utf-8",
      json: "application/json; charset=utf-8",
      txt: "text/plain; charset=utf-8",
      md: "text/markdown; charset=utf-8",
      png: "image/png",
      jpg: "image/jpeg",
      jpeg: "image/jpeg",
      gif: "image/gif",
      webp: "image/webp",
      svg: "image/svg+xml",
      ico: "image/x-icon",
      woff: "font/woff",
      woff2: "font/woff2",
      ttf: "font/ttf",
    },

    /** 黑名单扩展名：出现在文件名任一段（含多段扩展名如 shell.php.png）即拒绝。 */
    blockedExtensions: [
      // 服务端脚本
      "php", "phtml", "php3", "php4", "php5", "php7", "php8", "phar", "pht", "phps",
      "jsp", "jspx", "jsw", "jsv", "asp", "aspx", "ashx", "asmx", "axd", "cfm", "cfml",
      "cgi", "pl", "pm", "py", "pyc", "pyo", "pyw", "rb", "erb", "rhtml", "go", "rs",
      "java", "class", "jar", "war", "ear", "groovy", "scala", "kt", "lua", "tcl",
      "ts", "tsx", "jsx", "vue", "svelte", "coffee", "node",
      "ssi", "shtml", "stm", "xsl", "xslt", "wsf",
      // 可执行 / 脚本 / 安装包
      "exe", "dll", "so", "dylib", "bin", "com", "scr", "msi", "msp", "msix", "app",
      "dmg", "pkg", "deb", "rpm", "apk", "ipa", "run", "elf",
      "sh", "bash", "zsh", "fish", "ksh", "csh", "bat", "cmd", "ps1", "psm1", "psd1",
      "vbs", "vbe", "hta", "jse", "reg", "lnk", "inf", "pif", "gadget",
      // 字节码 / 中间产物
      "wasm", "wat", "pyd", "beam", "swf", "xap", "xbap", "dex", "odex", "oat",
      // 服务配置与敏感文件
      "htaccess", "htpasswd", "ini", "conf", "config", "env", "toml", "yaml", "yml",
      "pem", "key", "crt", "p12", "pfx", "jks", "keystore", "kdbx", "sql", "sqlite", "db",
      "log", "bak", "old", "orig", "swp", "tmp", "map",
      // 压缩包（禁止 ZIP 解压，也禁止直接上传压缩包）
      "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "lz", "lzma", "cab",
    ],

    /** 黑名单文件名（不区分大小写，整文件名匹配） */
    blockedFilenames: [
      ".htaccess", ".htpasswd", "web.config", "wrangler.toml", "wrangler.json",
      "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
      "composer.json", "composer.lock", "dockerfile", "makefile", "robots.txt.bak",
      "thumbs.db", "desktop.ini", "readme.env", "id_rsa", "id_ed25519",
    ],

    /** 黑名单目录名（路径任一段匹配即拒绝） */
    blockedDirectories: [
      "node_modules", ".git", ".svn", ".hg", "__pycache__", "vendor", "cgi-bin",
      "wp-admin", "wp-content", "wp-includes", "_worker", "functions",
    ],

    /** 内容检查：签名与语法层面的二次校验（防止“改后缀”绕过） */
    content: {
      enabled: true,
      /** 文件头命中这些签名一律拒绝（无论扩展名） */
      forbiddenSignatures: [
        { name: "ELF", bytes: [0x7f, 0x45, 0x4c, 0x46] },
        { name: "PE/MZ", bytes: [0x4d, 0x5a] },
        { name: "Mach-O 32", bytes: [0xfe, 0xed, 0xfa, 0xce] },
        { name: "Mach-O 64", bytes: [0xfe, 0xed, 0xfa, 0xcf] },
        { name: "Mach-O fat", bytes: [0xca, 0xfe, 0xba, 0xbe] },
        { name: "ZIP/JAR/DOCX", bytes: [0x50, 0x4b, 0x03, 0x04] },
        { name: "WASM", bytes: [0x00, 0x61, 0x73, 0x6d] },
        { name: "Shebang", bytes: [0x23, 0x21] }, // "#!"
      ],
      /** 文本内容中出现这些服务端标记即拒绝（大小写不敏感） */
      forbiddenMarkers: ["<?php", "<?=", "<%", "<jsp:", "<cfscript", "#!/bin", "#!/usr"],
      /** 文本类（html/css/js/json/svg 等）必须是合法 UTF-8 且不含 NUL */
      requireUtf8Text: true,
      /** 图片/字体扩展名必须与魔数匹配 */
      verifyBinaryMagic: true,
      /** SVG 净化策略：拒绝而不是修改（避免静默改变用户内容） */
      svg: {
        rejectScripts: true,
        rejectEventHandlers: true,
        rejectExternalRefs: true, // 禁止 <image href="http..."> 等外链
        rejectEntities: true, // XXE 防护
        rejectForeignObject: true,
      },
      /** HTML 中禁止的标签（沙箱之外的额外防御） */
      htmlRejectTags: ["iframe", "frame", "frameset", "object", "embed", "applet"],
    },
  },

  // ---------- 用户站点响应策略 ----------
  siteResponse: {
    /** 站点页面的 CSP。sandbox 使其丧失同源权限。 */
    contentSecurityPolicy:
      "sandbox allow-scripts allow-forms allow-popups allow-downloads",
    htmlCacheControl: "no-cache",
    assetCacheControl: "public, max-age=3600",
    permissionsPolicy: "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  },

  // ---------- 速率限制（窗口内最大次数） ----------
  rateLimits: {
    login: { limit: 10, windowSeconds: 900 },
    loginAccount: { limit: 5, windowSeconds: 900 },
    register: { limit: 5, windowSeconds: 3600 },
    captcha: { limit: 30, windowSeconds: 600 },
    upload: { limit: 30, windowSeconds: 600 },
    adminWrite: { limit: 60, windowSeconds: 600 },
    verifyEmail: { limit: 10, windowSeconds: 900 },
    resendVerification: { limit: 3, windowSeconds: 3600 },
    changePassword: { limit: 5, windowSeconds: 900 },
  },

  // ---------- 邮件（默认 SMTP） ----------
  mail: {
    /**
     * smtp  ：默认。通过 SMTP 发送验证邮件（需设置 SMTP_USERNAME / SMTP_PASSWORD Secret）
     * dev   ：仅本地开发。验证令牌在接口响应中返回。生产环境禁止使用。
     * none  ：不发送邮件（只能靠 BOOTSTRAP_TOKEN 完成管理员初始化）
     */
    mode: "smtp",
    from: "noreply@example.com",
    fromName: "静态建站",
    subject: "请验证您的邮箱",
    smtp: {
      host: "smtp.example.com",
      port: 465,
      /**
       * implicit：TLS 直连（常见 465 端口）
       * starttls：明文连接后升级 TLS（常见 587 端口）
       * none    ：不加密（禁止用于生产，仅用于本地测试服务器）
       */
      tls: "implicit",
      timeoutMs: 15000,
      /** 是否要求服务器证书链有效（Workers 默认校验，此项作为文档化的强制开关） */
      requireAuth: true,
    },
  },

  // ---------- 审计 ----------
  audit: {
    retentionDays: 90,
  },
};

export default config;
