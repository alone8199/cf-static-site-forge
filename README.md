# cf-static-site-forge

基于 **Cloudflare Workers** 的静态建站与 HTML 上传托管平台（仅静态部署，不执行任何服务端代码）。

- 用户注册 / 登录（图片验证码、登录速率限制与递增延迟、邮箱验证）
- 环境变量控制的超级用户（`ADMIN_EMAILS` / `ADMIN_USER_IDS`），不能通过注册或请求体授予
- 站点创建、多文件上传（白名单扩展名、路径防穿越、配额、原子提交与回滚）
- 用户站点部署在独立通配符子域 `{siteId}.sites.example.com`，与主应用 `app.example.com` 隔离
- 管理后台：用户列表与禁用、站点删除、审计日志

技术栈：Workers + TypeScript、Hono、zod、D1（数据）、R2（静态文件）、KV（验证码与速率限制）、WebCrypto。

---

## 目录结构

```
.
├── migrations/0001_init.sql        D1 表结构
├── public/                         前端（登录/注册/站点/上传/管理后台）
│   ├── index.html
│   ├── app.js                      无内联脚本，兼容严格 CSP
│   └── app.css
├── src/
│   ├── index.ts                    入口：Host 分流、错误处理、定时清理
│   ├── env.ts                      环境绑定与限制参数
│   ├── auth/
│   │   ├── roles.ts                超级用户判定（每次请求实时计算）
│   │   ├── session.ts              会话、Cookie、CSRF token
│   │   └── mail.ts                 邮件适配器（none / dev / webhook）
│   ├── middleware/auth.ts          requireAuth / requireSuperAdmin / CSRF / Origin
│   ├── db/users.ts                 用户表参数化查询
│   ├── lib/
│   │   ├── crypto.ts               PBKDF2、HMAC、随机数、常量时间比较
│   │   ├── captcha.ts              图片验证码（答案 HMAC 存 KV，一次性）
│   │   ├── captcha-svg.ts          干扰线 / 噪点 / 扭曲的 SVG 渲染
│   │   ├── turnstile.ts            验证码适配器（image / turnstile 预留）
│   │   ├── ratelimit.ts            KV 固定窗口速率限制
│   │   ├── audit.ts                审计日志（IP 只存 HMAC）
│   │   ├── validate.ts             zod 输入校验
│   │   ├── errors.ts               统一错误，不泄露内部细节
│   │   └── http.ts                 JSON 解析、安全响应头
│   ├── routes/
│   │   ├── auth.ts                 /api/auth/*
│   │   ├── captcha.ts              /api/captcha
│   │   ├── sites.ts                /api/sites/*（含上传）
│   │   ├── admin.ts                /api/admin/*
│   │   └── bootstrap.ts            /api/bootstrap（一次性管理员初始化）
│   └── sites/
│       ├── paths.ts                路径规范化与防穿越
│       ├── filetypes.ts            扩展名白名单 / 黑名单
│       ├── store.ts                站点、文件、R2 暂存与原子提交
│       └── serve.ts                用户站点静态文件服务
├── test/security.test.ts           安全单元测试
├── docs/SECURITY_TESTS.md          安全测试清单与 curl 示例
├── wrangler.toml
├── package.json  tsconfig.json  .dev.vars.example  .gitignore
```

---

## 快速开始（本地）

```bash
npm install
cp .dev.vars.example .dev.vars        # 填入随机生成的 Secret（见下）
npm run db:migrate:local
npm run dev
npm test
```

生成 Secret：

```bash
openssl rand -hex 32   # 分别用于 CAPTCHA_SECRET / IP_HASH_SECRET / SESSION_SECRET
```

本地邮件：在 `.dev.vars` 中设置 `MAIL_MODE=dev`，注册响应会返回 `devVerificationToken`，
用于调用 `/api/auth/verify-email`。**切勿在生产环境启用 dev 模式。**

---

## 部署

### 1. 创建资源

```bash
wrangler d1 create cf_static_site_forge          # 把 database_id 填入 wrangler.toml
wrangler kv namespace create KV                  # 把 id 填入 wrangler.toml
wrangler r2 bucket create cf-static-site-forge-sites
```

### 2. 设置 Secret（不要写入 wrangler.toml）

```bash
wrangler secret put CAPTCHA_SECRET
wrangler secret put IP_HASH_SECRET
wrangler secret put SESSION_SECRET
wrangler secret put BOOTSTRAP_TOKEN        # 可选，见“管理员初始化”
```

### 3. 配置变量

编辑 `wrangler.toml` 中 `[vars]`：

| 变量 | 说明 |
| --- | --- |
| `APP_ORIGIN` | 主应用来源，例如 `https://app.example.com`。用于 Origin 校验 |
| `SITES_ROOT_DOMAIN` | 用户站点根域，例如 `sites.example.com` |
| `SITES_SCHEME` | 站点协议，生产为 `https` |
| `ADMIN_EMAILS` | 超级用户邮箱列表，逗号分隔 |
| `ADMIN_USER_IDS` | 可选，超级用户 ID 列表，逗号分隔 |
| `SESSION_TTL_SECONDS` | 会话有效期，默认 86400 |
| `PBKDF2_ITERATIONS` | 密码迭代次数，默认 210000，下限 100000 |
| `CAPTCHA_TTL_SECONDS` / `CAPTCHA_MAX_ATTEMPTS` | 验证码有效期（默认 300 秒）与最大尝试次数（默认 3） |
| `CAPTCHA_PROVIDER` | `image`（默认）或 `turnstile` |
| `MAX_FILE_BYTES` / `MAX_UPLOAD_BYTES` / `MAX_SITE_BYTES` / `MAX_SITE_FILES` | 单文件、单次上传、站点总量、文件数上限 |
| `MAIL_MODE` | `none`（默认）/ `dev` / `webhook` |

Secrets 清单：`CAPTCHA_SECRET`、`IP_HASH_SECRET`、`SESSION_SECRET`、可选 `BOOTSTRAP_TOKEN`、
`MAIL_WEBHOOK_URL`（webhook 模式）、`TURNSTILE_SECRET`（Turnstile 模式）。

### 4. 迁移与发布

```bash
npm run db:migrate:remote
npm run deploy
```

### 5. 域名与通配符子域

1. 在 Cloudflare DNS 中为 `example.com` 配置：
   - `app.example.com` → 指向 Worker 路由（已在 `wrangler.toml` 的 `routes` 中声明）
   - `*.sites.example.com` → 同样指向 Worker（通配符记录需代理 / Proxied）
2. 需要 Cloudflare Universal SSL 或 Advanced Certificate 覆盖 `*.sites.example.com`。
3. **不要**把 `sites.example.com` 与 `app.example.com` 设为同一域名或父子共享 Cookie。
   主应用 Cookie 使用 `__Host-` 前缀，无 Domain 属性，因此不会发送到站点子域。

---

## 管理员配置

超级用户判定规则（每次请求实时计算，环境变量变更后新请求生效）：

- 账号 **邮箱已验证** 且状态为 `active`；并且
- 邮箱在 `ADMIN_EMAILS` 中，**或** 用户 ID 在 `ADMIN_USER_IDS` 中。

> 规格允许“ID 白名单”不要求验证；本实现更严格，两条路径都要求邮箱已验证。

**无邮件服务时的初始化（BOOTSTRAP_TOKEN）：**

1. `wrangler secret put BOOTSTRAP_TOKEN`（至少 32 字符随机串）。
2. 用 `ADMIN_EMAILS` 中的邮箱正常注册（此时邮箱未验证，**没有任何管理员权限**）。
3. 调用一次初始化接口，把该邮箱标记为已验证：

   ```bash
   curl -X POST https://app.example.com/api/bootstrap \
     -H 'content-type: application/json' \
     -d '{"token":"<BOOTSTRAP_TOKEN>","email":"admin@example.com"}'
   ```

4. 立即删除 Secret：`wrangler secret delete BOOTSTRAP_TOKEN`。
5. 该接口只能成功一次（KV 中写入 `bootstrap:consumed`）。

明确说明：**不能仅凭未验证邮箱授予管理员。** 未验证账号的 `resolveRole()` 恒为非管理员。
持有 `BOOTSTRAP_TOKEN` 的运维人员是初始化信任根，请妥善保管。

环境变量指定的超级用户**不能**在 UI 或 API 中被禁用或删除（返回 403）。

---

## 关键设计说明

**认证与会话**
- 密码：PBKDF2-SHA256，每用户 16 字节随机盐，迭代次数可配置。
- 会话：随机 token 放在 `__Host-sid` Cookie（HttpOnly、Secure、SameSite=Strict、Path=/）；数据库只存 SHA-256 哈希。
- 修改密码后吊销该用户全部会话并重新签发当前会话。
- 登录失败：先按 IP 与账号做速率限制；连续 5 次失败锁定 15 分钟；失败后递增延迟（上限 2 秒）；用户不存在时也执行一次哈希以缩小时序差异；错误文案统一。

**CSRF**
- 所有状态变更接口要求 `X-CSRF-Token` 头与会话中的 token 常量时间比较一致，
  并校验 `Origin`（若存在）必须等于 `APP_ORIGIN`。SameSite=Strict 作为第二层防护。

**图片验证码**
- 4–6 位，排除 `0 O 1 I L`；答案用 `CAPTCHA_SECRET` HMAC 后存 KV，TTL 5 分钟。
- 一次性：校验后立即删除；错误超过上限立即失效；失败统一返回同一文案。
- 图片为 SVG（干扰线、噪点、旋转抖动）。答案不写入日志或响应头。
- **安全性说明**：图片验证码对自动化脚本和 OCR 的抵抗力弱于 Cloudflare Turnstile。
  生产环境建议设置 `CAPTCHA_PROVIDER=turnstile` 并在前端接入 Turnstile widget。
  注意：KV 非原子，并发重放存在极小窗口，应配合速率限制与 Turnstile 使用。

**站点上传**
- 路径规范化：拒绝 `..`、`.`、绝对路径、反斜杠、空字节、控制字符、重复斜杠、隐藏文件、超深路径与非 ASCII 安全字符。
- 扩展名白名单；黑名单覆盖多段扩展名（如 `shell.php.png`）。
- 每个文件的 R2 key 由服务端生成：`users/{ownerId}/sites/{siteId}/{uploadId}/{path}`。
  用户路径不参与寻址，只作为 `files.path` 元数据。
- 原子性：先把对象写入本次 `uploadId` 前缀（暂存）；再用一个 D1 `batch`（事务）同时 upsert 文件元数据并重算站点总量；
  提交失败则删除暂存对象（回滚）；提交成功后清理被替换的旧对象。
- 文件名即目标路径（前端用 `new File([blob], "css/app.css")` 或同等方式提交）。
- 不支持 ZIP 上传（避免 zip bomb）。

**用户站点隔离**
- 站点子域只服务 `GET/HEAD`，响应不设置任何 Cookie，不读取主应用 Cookie。
- 响应头：`X-Content-Type-Options: nosniff`、`Content-Security-Policy: sandbox ...`（沙箱，无同源权限）、
  `Referrer-Policy`、`Permissions-Policy`、`X-Frame-Options`、`Cross-Origin-Resource-Policy`。
- 站点请求永远不进入主应用路由。

**主应用**
- 严格 CSP：`default-src 'none'; script-src 'self'; ...`，无内联脚本。
- 统一错误格式，不返回堆栈、SQL、R2 key 或环境变量；服务端只记录错误类型名。

**审计日志**
- 记录操作者 ID、动作、目标、IP 的 HMAC 哈希（`IP_HASH_SECRET`）、结果、时间。
- 不记录密码、验证码答案、session token 或验证 token。
- 定时任务保留 90 天。

---

## 安全建议（部署时启用）

- **Cloudflare WAF**：启用托管规则集，对 `/api/*` 启用自定义规则。
- **Rate Limiting 规则**：对 `/api/auth/login`、`/api/auth/register`、`/api/captcha`、`/api/sites/*/upload` 设置边缘限速（应用内 KV 限速只是补充）。
- **Bot Fight Mode / Super Bot Fight Mode**：对注册与登录路径开启。
- **Turnstile**：生产环境替换图片验证码。
- **访问日志与告警**：启用 Logpush，对 4xx/5xx 突增、`bootstrap` 调用、管理员操作设置告警。
- **密钥轮换**：`CAPTCHA_SECRET` 与 `IP_HASH_SECRET` 轮换会使未过期验证码失效、IP 哈希不再可比对，请在低峰期进行。
- **备份**：D1 定期导出，R2 启用版本控制或生命周期策略。

---

## MVP 与生产增强项

**MVP（本仓库已实现）**
- 注册 / 登录 / 退出 / 当前用户 / 改密 / 邮箱验证（dev 与 webhook 适配器）
- 环境变量超级用户、BOOTSTRAP_TOKEN 一次性初始化
- 图片验证码（一次性、HMAC 存储、TTL、尝试次数）
- 站点 CRUD、多文件上传、白名单、路径防穿越、配额、暂存 + 原子提交 + 回滚
- 用户站点子域隔离与安全响应头
- 管理后台 API：用户列表、禁用 / 启用、站点列表与删除、审计日志
- 前端：登录、注册、站点列表、创建站点、上传（含进度）、验证码刷新、管理后台、修改密码
- D1 迁移、定时清理、安全单元测试

**生产增强（已预留或仅有说明，建议上线前完成）**
- Turnstile 完整前端接入（适配器已预留：`src/lib/turnstile.ts`）
- 真实邮件服务（`MAIL_MODE=webhook` 仅提供调用骨架，需对接你的邮件提供商）
- 精确限速：KV 非原子，高并发下可换 Durable Objects 实现计数器
- 上传后的内容扫描（如恶意软件扫描）、SVG 净化
- 站点级别的自定义域名、HTTP 缓存失效（purge）
- 更细的管理员角色（只读管理员等）与操作二次确认
- 会话设备管理（列出并吊销其他设备会话）
- 完整的端到端测试（Miniflare / `@cloudflare/vitest-pool-workers`）

---

## 已知限制

- 注册时“邮箱已注册”会返回 409，存在邮箱枚举风险；如需更强隐私，可改为统一响应并通过邮件告知。
- 站点配额与站点数量在并发上传时存在极小竞争窗口（最终会被批量事务重算修正）。
- 文件名仅允许 ASCII 安全字符（字母、数字、`.`、`_`、`-`），不支持空格与中文路径。
- 不提供目录列表；目录请求映射到 `index.html`，不存在则 404。
