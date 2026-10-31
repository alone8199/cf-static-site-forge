# cf-static-site-forge

基于 **Cloudflare Workers** 的静态建站与 HTML 上传托管平台（仅静态部署，不执行任何服务端代码）。

- 用户注册 / 登录（图片验证码、失败锁定与递增延迟、邮箱验证）
- 环境变量控制的超级用户（`ADMIN_EMAILS` / `ADMIN_USER_IDS`），不能通过注册或请求体授予
- 站点创建与多文件上传：扩展名白名单 + 黑名单、文件名/目录黑名单、内容签名检查、SVG 净化、路径防穿越、配额、原子提交与回滚
- 用户站点部署在独立通配符子域 `{siteId}.sites.example.com`，与主应用 `app.example.com` 隔离
- 默认通过 **SMTP** 发送验证邮件（支持隐式 TLS 与 STARTTLS）
- 管理后台：用户列表与禁用、站点删除、审计日志

技术栈：Workers + TypeScript、Hono、zod、D1（数据）、KV（限速、验证码、用户站点文件）、WebCrypto。

> 存储说明：用户站点文件存放在 Workers KV 中（单值上限 25 MiB，免费套餐每天 1,000 次写入，每个上传文件和每次替换/删除都计入写入次数）。
> 如需更大容量或更多写入，请升级套餐，或改用 S3 兼容存储（需要替换存储层实现）。
> KV 是最终一致的：文件刚上传后，其他边缘节点可能需要约 60 秒才能读到新内容。

---

## 配置体系

系统有两类配置，分开管理：

| 类别 | 位置 | 示例 |
| --- | --- | --- |
| **非机密配置**（可提交仓库） | `config/app.config.ts` | 域名、限额、SMTP 服务器、密码策略、黑名单、速率限制 |
| **超级用户** | `wrangler.toml` 的 `[vars]` | `ADMIN_EMAILS`、`ADMIN_USER_IDS` |
| **机密**（只走 Secret） | `wrangler secret put` / `.dev.vars` | `CAPTCHA_SECRET`、`IP_HASH_SECRET`、`SMTP_USERNAME`、`SMTP_PASSWORD`、`BOOTSTRAP_TOKEN`、`TURNSTILE_SECRET` |

**修改 `config/app.config.ts` 后执行 `npm run deploy` 生效**（配置在构建时打包进 Worker，启动时会校验，配置错误会直接报错而不是静默降级）。

`config/app.config.ts` 主要分区：

- `app` / `sites`：主应用来源、站点根域、协议、每用户站点上限
- `session` / `password` / `auth`：会话时长、密码策略、锁定阈值与时长、验证链接有效期
- `captcha`：提供方（image / turnstile）、有效期、尝试次数、长度与字符集
- `upload`：单文件、单次、站点总量、文件数、路径长度与深度
- `security.allowedExtensions`：允许的扩展名与 Content-Type
- `security.blockedExtensions` / `blockedFilenames` / `blockedDirectories`：黑名单
- `security.content`：文件头签名黑名单、服务端标记、UTF-8 检查、魔数校验、SVG 与 HTML 规则
- `siteResponse`：用户站点的沙箱 CSP、缓存策略
- `rateLimits`：各接口的速率限制
- `mail`：邮件模式与 SMTP 参数
- `audit`：审计日志保留天数

启动校验会拒绝的配置示例：`app.origin` 非 https、站点根域与主应用域重叠、允许与黑名单冲突、
迭代次数低于下限、验证码长度越界、明文 SMTP 指向非本机地址。

---

## SMTP 邮件配置（默认）

在 `config/app.config.ts` 中设置：

```ts
mail: {
  mode: "smtp",
  from: "noreply@example.com",       // 必须是你的 SMTP 账号可代发的地址
  fromName: "静态建站",
  subject: "请验证您的邮箱",
  smtp: {
    host: "smtp.example.com",
    port: 465,
    tls: "implicit",                  // 465 常用；587 用 "starttls"
    timeoutMs: 15000,
    requireAuth: true,
  },
},
```

设置凭据（不要写进配置文件）：

```bash
wrangler secret put SMTP_USERNAME
wrangler secret put SMTP_PASSWORD     # 多数服务商需要使用“应用专用密码/授权码”
```

常见配置：

| 服务商 | host | port | tls |
| --- | --- | --- | --- |
| 通用 SSL | `smtp.<域名>` | 465 | `implicit` |
| 通用 STARTTLS | `smtp.<域名>` | 587 | `starttls` |
| 腾讯企业邮 | `smtp.exmail.qq.com` | 465 | `implicit` |
| Gmail | `smtp.gmail.com` | 465 | `implicit`（需应用专用密码） |
| Amazon SES | `email-smtp.<region>.amazonaws.com` | 587 | `starttls` |

安全行为：

- 凭据只在加密连接上发送（`tls: "none"` 且配置了凭据时直接拒绝）。
- 配置校验阻止 `tls: "none"` 指向非本机地址。
- 头部字段拒绝 CR/LF，防止邮件头注入；主题与发件人名使用 RFC 2047 编码。
- 失败只记录步骤名（如 `smtp_auth`），不记录地址、令牌或服务器原始响应。
- 发送失败不会阻断注册：用户可稍后使用“重新发送验证邮件”。

其它模式：

- `mode: "dev"`：仅本地开发，验证令牌在响应中返回。**生产禁止。**
- `mode: "none"`：不发邮件，只能用 `BOOTSTRAP_TOKEN` 初始化管理员。

---

## 快速开始（本地）

```bash
npm install
cp .dev.vars.example .dev.vars        # 填入 Secret（见下）
npm run db:migrate:local
npm run dev
npm test
```

生成随机密钥：

```bash
openssl rand -hex 32
```

本地调试邮件：可在 `config/app.config.ts` 临时设 `mail.mode = "dev"`（令牌在注册响应中返回），
或把 `mail.smtp.host` 指向本机 SMTP 测试服务器并设 `tls: "none"`（仅限 localhost）。

---

## 部署

```bash
# 1. 创建资源
wrangler d1 create cf_static_site_forge        # 把 database_id 填入 wrangler.toml
wrangler kv namespace create KV                # 限速/验证码数据，id 填入 wrangler.toml 的 binding = "KV"
wrangler kv namespace create FILES_KV          # 用户站点文件，id 填入 binding = "FILES_KV"

# 2. 设置机密
wrangler secret put CAPTCHA_SECRET
wrangler secret put IP_HASH_SECRET
wrangler secret put SMTP_USERNAME
wrangler secret put SMTP_PASSWORD
wrangler secret put BOOTSTRAP_TOKEN            # 可选，见“管理员配置”

# 3. 修改 config/app.config.ts（域名、SMTP 等）与 wrangler.toml（ADMIN_EMAILS、routes）

# 4. 迁移与发布
npm run db:migrate:remote
npm run deploy
```

### 域名与通配符子域

1. DNS 中为 `example.com` 配置：`app.example.com` 与 `*.sites.example.com`，均为 Proxied。
2. 证书需覆盖 `*.sites.example.com`（Universal SSL 或 Advanced Certificate）。
3. `app.example.com` 与 `sites.example.com` **不要**共享 Cookie 域。主应用 Cookie 使用 `__Host-` 前缀、无 Domain 属性，不会发送到站点子域。
4. 域名同时需要在 `config/app.config.ts`（`app.origin`、`sites.rootDomain`）与 `wrangler.toml`（`routes`）中保持一致。

---

## 管理员配置

超级用户判定（每次请求实时计算，修改环境变量后新请求生效）：

- 账号 **邮箱已验证** 且状态 `active`，并且：邮箱在 `ADMIN_EMAILS` 中，**或** 用户 ID 在 `ADMIN_USER_IDS` 中。

> 规格允许“ID 白名单”不要求验证，本实现更严格：两条路径都要求邮箱已验证。

**一次性初始化（`BOOTSTRAP_TOKEN`）**，用于 `mail.mode = "none"` 或 SMTP 暂不可用时：

1. 设置 `BOOTSTRAP_TOKEN`（至少 32 字符随机串）。
2. 用 `ADMIN_EMAILS` 中的邮箱正常注册（此时未验证，**没有任何管理员权限**）。
3. 调用一次：

   ```bash
   curl -X POST https://app.example.com/api/bootstrap \
     -H 'content-type: application/json' \
     -d '{"token":"<BOOTSTRAP_TOKEN>","email":"admin@example.com"}'
   ```

4. 立即删除：`wrangler secret delete BOOTSTRAP_TOKEN`。

说明：该接口只能成功一次（KV 中写入 `bootstrap:consumed`）；只接受 `ADMIN_EMAILS` 中的邮箱；
未配置 `BOOTSTRAP_TOKEN` 时接口对外不可见（404）。
**不能仅凭未验证邮箱授予管理员**：未验证账号的角色恒为非管理员。持有 `BOOTSTRAP_TOKEN` 的运维人员是初始化信任根。

环境变量指定的超级用户**不能**在 UI 或 API 中被禁用或删除（返回 403）。

---

## 文件上传安全策略

上传流程：限流 → 站点归属 → 验证码 → 逐文件校验 → 配额 → 暂存 → 原子提交 → 清理旧对象。
**整批拒绝**：任一文件不合规，本次上传全部不写入，被拒绝的上传写入审计日志（只记录错误码）。

逐文件校验依次为：

1. **路径规范化**：拒绝 `..`、`.`、绝对路径、反斜杠、空字节、控制字符、重复斜杠、隐藏文件、
   尾随点或空格、Windows 保留名（`con`、`nul`…）、URL 编码分隔符（`%2f`、`%5c`…）、非 ASCII、超长、超深。
2. **目录黑名单**：`node_modules`、`.git`、`vendor`、`cgi-bin`、`wp-admin` 等。
3. **文件名黑名单**：`.htaccess`、`web.config`、`wrangler.toml`、`package.json`、锁文件、密钥文件等。
4. **扩展名**：必须在白名单内；**黑名单覆盖文件名的每一段**，因此 `shell.php.png`、`setup.exe.txt`、`backup.sql.html` 全部拒绝。
   黑名单包含服务端脚本（php/jsp/asp/py/rb/go…）、可执行与安装包（exe/dll/so/sh/bat/ps1/apk…）、
   字节码（wasm/swf…）、配置与密钥（ini/conf/env/pem/key/sql/db/map…）、压缩包（zip/tar/rar…）。
5. **内容签名（防改后缀）**：文件头命中 ELF、PE/MZ、Mach-O、ZIP、WASM、shebang 即拒绝，**与扩展名无关**。
6. **魔数一致**：png/jpg/gif/webp/ico/woff/woff2/ttf 必须与其真实魔数匹配。
7. **文本检查**：html/css/js/json/txt/md/svg 必须是合法 UTF-8，不得含 NUL。
8. **服务端标记**：`<?php`、`<?=`、`<%`、`<jsp:`、`<cfscript`、`#!/bin` 等一律拒绝。
9. **SVG 净化（拒绝而非修改）**：拒绝 `<script>`、事件属性（`onload=` 等）、外部引用（`href`/`src` 指向 http/数据 URL）、
   实体声明（XXE）、`foreignObject`、`javascript:` 协议。
10. **HTML**：拒绝 `iframe`、`frame`、`object`、`embed`、`applet` 等可嵌入外部内容的标签。
11. **大小写冲突**：`A.html` 与 `a.html` 不能同时存在（同一批或与已有文件冲突）。
12. **配额**：单文件、单次总量、站点总量、文件数量，超限返回明确错误码。

所有策略都在 `config/app.config.ts` 的 `security` 节中，可按需增删。
注意：拒绝式净化比“修改后放行”更安全，但可能误伤合法文件，请根据业务调整。

### 用户站点的响应隔离

- 只服务 `GET` / `HEAD`，不设置任何 Cookie，不读取主应用 Cookie。
- 默认 CSP 为 `sandbox allow-scripts allow-forms allow-popups allow-downloads`（沙箱，无同源权限）。
- `X-Content-Type-Options: nosniff`、`Referrer-Policy`、`Permissions-Policy`、`Cross-Origin-Resource-Policy: same-site`。
- 站点请求永远不进入主应用路由。

---

## 其它安全设计

**认证与会话**
- 密码：PBKDF2-SHA256，每用户 16 字节随机盐，迭代次数不低于配置下限。
- 会话：随机 token 放在 `__Host-sid`（HttpOnly、Secure、SameSite=Strict、Path=/）；数据库只存 SHA-256 哈希。
- 修改密码后吊销该用户全部会话，并为当前请求重新签发。
- 登录：按 IP 与账号限流；连续失败锁定；失败后递增延迟（有上限）；用户不存在也执行一次哈希；错误文案统一。

**CSRF**：状态变更接口要求 `X-CSRF-Token`（与会话 token 常量时间比较），并校验 `Origin`（若存在）等于配置中的主应用域。

**验证码**：答案 HMAC（`CAPTCHA_SECRET`）后存 KV，一次性使用，超过尝试次数立即失效，失败统一文案。
字符集排除 `0 O 1 I L`。SVG 含干扰线、噪点、旋转与抖动。
**安全性说明**：图片验证码弱于 Cloudflare Turnstile。生产建议设置 `captcha.provider = "turnstile"` 并在前端接入 widget。

**审计**：记录操作者、动作、目标、IP 的 HMAC 哈希、结果、时间。不记录密码、验证码答案、会话 token、验证令牌或文件内容。

**错误响应**：统一 JSON，不返回堆栈、SQL、存储键或环境变量；服务端只记录错误类型名。

---

## 建议的 Cloudflare 边缘防护

- **WAF**：启用托管规则集，对 `/api/*` 启用自定义规则。
- **Rate Limiting 规则**：对 `/api/auth/login`、`/api/auth/register`、`/api/captcha`、`/api/sites/*/upload` 设边缘限速（应用内 KV 限速是补充）。
- **Bot Fight Mode / Super Bot Fight Mode**：注册与登录路径开启。
- **Turnstile**：替换图片验证码。
- **Logpush 与告警**：4xx/5xx 突增、`bootstrap` 调用、管理员操作。

---

## 测试

```bash
npm test
```

- `test/security.test.ts`：路径穿越、扩展名与黑名单、超级用户判定、密码哈希、Host 分流、验证码渲染。
- `test/content.test.ts`：改后缀伪装、魔数、服务端标记、编码、SVG 与 HTML 规则。

完整的手工安全测试清单与 curl 示例见 `docs/SECURITY_TESTS.md`。

---

## 已知限制

- 注册时“邮箱已注册”返回 409，存在邮箱枚举风险；如需更强隐私，可统一响应并改为邮件通知。
- 速率限制基于 KV，最终一致、非原子；高并发下可能有少量超额。生产请配合 Cloudflare Rate Limiting，或改用 Durable Objects。
- 验证码的 KV 读-删操作非原子，理论上存在极小的并发重放窗口。
- 文件名仅允许 ASCII 安全字符（字母、数字、`.`、`_`、`-`），不支持空格与中文路径。
- 不提供目录列表；目录请求映射到 `index.html`，不存在则 404。
- SMTP 客户端基于 `cloudflare:sockets` 自研（不依赖第三方库），仅实现 AUTH PLAIN/LOGIN 与基本的 STARTTLS；不支持附件与 HTML 邮件。
- 内容检查是启发式的，不能替代专业的恶意软件扫描；如需更高安全性，可接入外部扫描服务。
