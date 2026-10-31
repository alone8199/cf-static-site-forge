# 安全测试清单

约定：`$APP` = `https://app.example.com`，`$SITE` = `https://<siteId>.sites.example.com`。
下列 curl 示例假设已登录并保存 Cookie 到 `cj.txt`，CSRF token 来自登录或 `/api/auth/me` 响应。

```bash
APP=https://app.example.com
SITE_ROOT=sites.example.com
CSRF="<从登录响应的 csrfToken 复制>"
```

---

## 1. 单元测试

```bash
npm test
```

覆盖：路径穿越、扩展名白名单与黑名单（含多段与中间段）、黑名单文件名与目录、Windows 保留名、
超级用户判定（未验证不生效、大小写、禁用账号）、PBKDF2 哈希、Host 分流、验证码 SVG 渲染。
`test/content.test.ts` 覆盖内容级检查：改后缀伪装（ELF/PE/ZIP/WASM/shebang）、图片魔数匹配、
服务端标记（`<?php`、`<%`）、NUL 与非 UTF-8 文本、HTML 危险标签、SVG 脚本/事件/外链/XXE 净化。

> SMTP 客户端依赖 `cloudflare:sockets`，无法在 Node 环境直接单测，需用 `wrangler dev` 配合本地
> SMTP 测试服务器（如 MailHog 的 `tls=none` 本地模式，仅限开发）手工验证。

---

## 2. 越权（IDOR）

| 用例 | 步骤 | 期望 |
| --- | --- | --- |
| 读取他人站点列表 | 用户 A 调用 `GET /api/sites` | 只返回 A 的站点 |
| 删除他人站点 | A 调用 `DELETE /api/sites/<B的siteId>` | 404，站点未删除 |
| 上传到他人站点 | A 调用 `POST /api/sites/<B的siteId>/upload` | 404 |
| 普通用户访问管理接口 | A 调用 `GET /api/admin/users` | 403 |
| 普通用户管理员删除站点 | A 调用 `DELETE /api/admin/sites/<id>` | 403 |
| 伪造管理员字段 | `POST /api/auth/register` 请求体加入 `"role":"admin"` | 字段被忽略，`/api/auth/me` 中 `isSuperAdmin=false` |

```bash
curl -i -X DELETE "$APP/api/sites/<他人的siteId>" \
  -H "Cookie: __Host-sid=<A的会话>" -H "X-CSRF-Token: $CSRF"
# 期望：HTTP/1.1 404
```

---

## 3. 路径穿越

上传时 File 名称不得包含以下内容（均应返回 400 `invalid_path`）：

```
../../etc/passwd    /abs.html    a\b.html    a//b.html    a/./b.html    .env    dir/.htaccess
```

```bash
curl -i -X POST "$APP/api/sites/$SID/upload" \
  -H "Cookie: __Host-sid=$SESS" -H "X-CSRF-Token: $CSRF" \
  -F "captchaId=$CID" -F "captchaAnswer=$ANS" \
  -F "files=@local.html;filename=../../x.html"
# 期望：400 invalid_path
```

站点请求同样检查（解码后仍应被拒绝）：

```bash
curl -i "$SITE/%2e%2e/secret.html"        # 期望 404
curl -i "$SITE/a%5cb.html"                # 期望 404
```

---

## 4. SQL 注入

所有查询参数化。尝试在 `email`、`name`、`siteId`、`limit` 中注入：

```bash
curl -s -X POST "$APP/api/auth/login" -H 'content-type: application/json' \
  -d '{"email":"x@y.com'\'' OR 1=1 --","password":"x","captchaId":"...","captchaAnswer":"..."}'
# 期望：400 validation_error 或 401，不出现 SQL 错误信息
curl -s "$APP/api/admin/users?limit=1;DROP%20TABLE%20users"
# 期望：401/403 或 400（zod 拒绝非数字）
```

---

## 5. XSS

- 站点名称注入：`name` 设为 `<img src=x onerror=alert(1)>`，在站点列表与管理后台页面中应以纯文本显示（前端使用 `textContent`）。
- 用户站点：上传含 `<script>` 的 `index.html` 到 `$SITE`，脚本运行于站点源（沙箱 CSP），但无法读取主应用 Cookie（`__Host-sid` 不会发送到子域）：

  ```bash
  # 在站点页面中执行：document.cookie 不应包含 __Host-sid
  ```

- 主应用响应头检查：

  ```bash
  curl -sI "$APP/" | grep -i content-security-policy
  # 期望包含 default-src 'none'; script-src 'self'
  ```

---

## 6. CSRF

```bash
# 1) 无 X-CSRF-Token 的状态变更请求应被拒绝
curl -i -X POST "$APP/api/sites" -H "Cookie: __Host-sid=$SESS" \
  -H 'content-type: application/json' -d '{"name":"t"}'
# 期望：403 CSRF 校验失败

# 2) 来自其他来源的 Origin 应被拒绝
curl -i -X POST "$APP/api/sites" -H "Origin: https://evil.example" \
  -H "Cookie: __Host-sid=$SESS" -H "X-CSRF-Token: $CSRF" \
  -H 'content-type: application/json' -d '{"name":"t"}'
# 期望：403 请求来源不被允许
```

---

## 7. 暴力破解与速率限制

```bash
# 连续错误登录，观察第 5 次起锁定、响应含 Retry-After
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "%{http_code} " -X POST "$APP/api/auth/login" \
    -H 'content-type: application/json' \
    -d '{"email":"victim@example.com","password":"wrong","captchaId":"'$CID'","captchaAnswer":"x"}'
done
# 期望：最终返回 429（账号锁定 / 速率限制）
```

注册、验证码签发、上传、管理员写操作分别按 `src/lib/ratelimit.ts` 中的 `RULES` 限速。

---

## 8. 验证码重放与一次性

```bash
# 1) 获取验证码
curl -s "$APP/api/captcha" | tee cap.json
# 2) 使用正确答案提交一次（成功）
# 3) 用同一 captchaId 再次提交（期望：422 captcha_failed，记录已删除）
```

| 用例 | 期望 |
| --- | --- |
| 正确答案重放 | 第二次失败 |
| 错误答案 3 次后再提交正确答案 | 失败（超过 `CAPTCHA_MAX_ATTEMPTS`） |
| 超过 5 分钟后提交 | 失败（KV TTL 过期） |
| 不存在的 captchaId | 失败，且与答错返回相同文案 |
| 验证码答案不出现在日志中 | 检查 `wrangler tail` 输出 |

---

## 9. 超大文件与配额

```bash
# 单文件超过 MAX_FILE_BYTES（默认 5 MiB）
dd if=/dev/zero of=big.html bs=1M count=6
curl -i -X POST "$APP/api/sites/$SID/upload" ... -F "files=@big.html;filename=big.html"
# 期望：413 file_too_large

# 单次上传总量超过 MAX_UPLOAD_BYTES（默认 20 MiB）→ 413 upload_too_large
# 文件数超过 MAX_SITE_FILES（默认 500）→ 413 too_many_files
# 站点总量超过 MAX_SITE_BYTES（默认 100 MiB）→ 413 site_quota_exceeded
```

---

## 10. 非法扩展名

```bash
for f in shell.php x.phtml run.sh a.exe m.wasm s.py app.jsp shell.php.png archive.zip noext; do
  curl -s -o /dev/null -w "$f %{http_code}\n" -X POST "$APP/api/sites/$SID/upload" \
    -H "Cookie: __Host-sid=$SESS" -H "X-CSRF-Token: $CSRF" \
    -F "captchaId=$CID" -F "captchaAnswer=$ANS" -F "files=@local;filename=$f"
done
# 期望：全部 415
```

---

## 11. 跨用户删除

| 用例 | 期望 |
| --- | --- |
| 用户 A 删除 B 的站点 | 404，B 的站点与 存储对象均保留 |
| 管理员禁用环境变量超级用户 | 403 `环境变量指定的超级用户不可禁用` |
| 管理员禁用自己 | 409 `不能禁用自己` |
| 管理员删除站点后站点域访问 | 404 |

---

## 12. 管理员与超级用户

| 用例 | 期望 |
| --- | --- |
| 注册 `ADMIN_EMAILS` 中的邮箱（未验证） | `isSuperAdmin=false`，无法登录（需先验证） |
| 通过 `/api/bootstrap` 验证后登录 | `isSuperAdmin=true` |
| 修改 `ADMIN_EMAILS` 后，旧会话 | 下一次请求即按新配置计算角色 |
| 再次调用 `/api/bootstrap` | 409 `初始化令牌已使用` |
| 错误 BOOTSTRAP_TOKEN | 403 |
| 未配置 BOOTSTRAP_TOKEN | 404（接口不可见） |

---

## 13. 会话

| 用例 | 期望 |
| --- | --- |
| 退出后复用旧 Cookie | 401 |
| 修改密码后旧会话 | 401 |
| 会话过期 | 401，且记录被删除 |
| 数据库中会话表 | 只有 SHA-256 哈希，无明文 token |

```bash
wrangler d1 execute cf_static_site_forge --remote \
  --command "SELECT token_hash FROM sessions LIMIT 3"
# 期望：64 位十六进制字符串，不是 Cookie 中的值
```

---

## 14. 错误信息泄露

- 构造非法 JSON、超长字段、非法 Content-Type，检查响应中不含堆栈、SQL、存储键、`ADMIN_EMAILS` 等。
- 检查 `wrangler tail` 中 `unhandled_error` 只包含错误名称。

---

## 15. 上线前手工检查

- [ ] `wrangler.toml` 中没有真实 Secret
- [ ] `.dev.vars` 未提交（`.gitignore` 已包含）
- [ ] `config/app.config.ts` 中 `mail.mode` 生产为 `smtp`（或 `none`），不是 `dev`
- [ ] `mail.smtp.tls` 不是 `none`，且 SMTP 凭据已通过 Secret 设置
- [ ] `BOOTSTRAP_TOKEN` 已删除或确认不再需要
- [ ] `APP_ORIGIN` 与 `SITES_ROOT_DOMAIN` 指向正确域名
- [ ] WAF、Rate Limiting、Bot Fight Mode 已启用
- [ ] 访问日志与告警已配置
- [ ] 已确认站点子域请求不携带 `__Host-sid`
