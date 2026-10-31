import { describe, it, expect } from "vitest";
import { normalizeUploadPath, resolveRequestPath } from "../src/sites/paths";
import { classifyFile } from "../src/sites/filetypes";
import { resolveRole } from "../src/auth/roles";
import { hashPassword, verifyPassword, timingSafeEqual } from "../src/lib/crypto";
import { renderCaptchaSvg } from "../src/lib/captcha-svg";
import { siteIdFromHost } from "../src/sites/serve";
import type { Env } from "../src/env";

const env = {
  ADMIN_EMAILS: "admin@example.com, Ops@Example.com",
  ADMIN_USER_IDS: "abc123",
} as unknown as Env;

describe("路径规范化（防穿越）", () => {
  it.each([
    "../etc/passwd",
    "a/../b.html",
    "/abs.html",
    "a\\b.html",
    "a//b.html",
    "a/./b.html",
    ".env",
    "dir/.htaccess",
    "nul\0.html",
    "tab\t.html",
    "trailing/",
    "a/".repeat(9) + "x.html",
  ])("拒绝 %j", (p) => {
    expect(() => normalizeUploadPath(p)).toThrow();
  });

  it("接受合法相对路径", () => {
    expect(normalizeUploadPath("css/app.css")).toBe("css/app.css");
  });

  it("请求路径解码后仍然检查（%2e%2e、%5c）", () => {
    expect(resolveRequestPath("/%2e%2e/secret.html")).toBeNull();
    expect(resolveRequestPath("/a%5cb.html")).toBeNull();
    expect(resolveRequestPath("/")).toBe("index.html");
    expect(resolveRequestPath("/docs/")).toBe("docs/index.html");
  });
});

describe("文件类型白名单", () => {
  it.each(["shell.php", "x.php.png", "run.sh", "a.exe", "m.wasm", "s.py", "app.jsp", "x.phtml"])(
    "禁止 %s",
    (p) => {
      expect(() => classifyFile(p)).toThrow();
    },
  );

  it("允许静态文件并返回 Content-Type", () => {
    expect(classifyFile("index.html").contentType).toMatch(/^text\/html/);
    expect(classifyFile("img/logo.PNG").ext).toBe("png");
  });

  it("不在白名单中的扩展名拒绝", () => {
    expect(() => classifyFile("archive.zip")).toThrow();
    expect(() => classifyFile("noext")).toThrow();
  });
});

describe("超级用户判定", () => {
  const base = { id: "u1", email: "admin@example.com", status: "active" };

  it("已验证 + 在 ADMIN_EMAILS 中 → 超级用户（大小写不敏感）", () => {
    expect(resolveRole(env, { ...base, email_verified: 1 }).isSuperAdmin).toBe(true);
    expect(resolveRole(env, { ...base, email: "OPS@example.com", email_verified: 1 }).isSuperAdmin).toBe(true);
  });

  it("未验证邮箱即使在列表中也不是超级用户", () => {
    expect(resolveRole(env, { ...base, email_verified: 0 }).isSuperAdmin).toBe(false);
  });

  it("ADMIN_USER_IDS 也需要已验证", () => {
    const u = { id: "abc123", email: "x@y.com", status: "active" };
    expect(resolveRole(env, { ...u, email_verified: 0 }).isSuperAdmin).toBe(false);
    expect(resolveRole(env, { ...u, email_verified: 1 }).isSuperAdmin).toBe(true);
  });

  it("禁用账号不是超级用户", () => {
    expect(resolveRole(env, { ...base, email_verified: 1, status: "disabled" }).isSuperAdmin).toBe(false);
  });

  it("普通邮箱不是超级用户", () => {
    expect(resolveRole(env, { id: "u2", email: "user@example.com", email_verified: 1, status: "active" }).isSuperAdmin).toBe(false);
  });
});

describe("密码哈希", () => {
  it("PBKDF2 验证正确与错误密码（使用低迭代次数加速测试）", async () => {
    const rec = await hashPassword("Correct-Horse-1", 100000);
    expect(rec.salt.length).toBeGreaterThan(10);
    expect(await verifyPassword("Correct-Horse-1", rec)).toBe(true);
    expect(await verifyPassword("Wrong-Horse-1", rec)).toBe(false);
  });

  it("每次哈希使用不同盐", async () => {
    const a = await hashPassword("Same-Pass-1a", 100000);
    const b = await hashPassword("Same-Pass-1a", 100000);
    expect(a.salt).not.toBe(b.salt);
    expect(a.hash).not.toBe(b.hash);
  });

  it("timingSafeEqual 基本正确", () => {
    expect(timingSafeEqual("abc", "abc")).toBe(true);
    expect(timingSafeEqual("abc", "abd")).toBe(false);
    expect(timingSafeEqual("abc", "abcd")).toBe(false);
  });
});

describe("验证码渲染", () => {
  it("SVG 不包含明文以外的额外答案信息，且只输出 SVG", () => {
    const svg = renderCaptchaSvg("ABCD", "seed");
    expect(svg.startsWith("<svg")).toBe(true);
    expect(svg).toContain("ABCD".split("")[0]!);
    expect(svg).not.toMatch(/<script/i);
  });
});

describe("Host 分流", () => {
  const root = "sites.example.com";
  const sid = "0123456789abcdef0123456789abcdef";

  it("站点子域解析出站点 ID", () => {
    expect(siteIdFromHost(`${sid}.${root}`, root)).toBe(sid);
  });

  it("非法站点标签 → null（404）", () => {
    expect(siteIdFromHost(`app.${root}`, root)).toBeNull();
    expect(siteIdFromHost(`a.b.${root}`, root)).toBeNull();
    expect(siteIdFromHost(root, root)).toBeNull();
  });

  it("主应用域 → undefined（交给 API）", () => {
    expect(siteIdFromHost("app.example.com", root)).toBeUndefined();
  });
});
