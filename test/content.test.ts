import { describe, it, expect } from "vitest";
import { scanContent } from "../src/sites/content";
import { classifyFile } from "../src/sites/filetypes";
import { normalizeUploadPath } from "../src/sites/paths";

const enc = new TextEncoder();
const bytes = (s: string) => enc.encode(s);
const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d]);
const ELF = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
const PE = new Uint8Array([0x4d, 0x5a, 0x90, 0x00]);
const ZIP = new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00]);
const WASM = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

describe("文件名与扩展名黑名单（多段与中间段）", () => {
  it.each([
    "shell.php.png", // 中间段 php
    "evil.phtml.jpg",
    "setup.exe.txt", // 中间段 exe
    "backup.sql.html", // 中间段 sql
    "bundle.tar.gz",
    "x.zip",
    ".htaccess",
    "wrangler.toml",
    "package.json",
    "app.key",
    "x.map",
  ])("拒绝 %s", (p) => {
    expect(() => classifyFile(p)).toThrow();
  });

  it("目录黑名单：node_modules / .git / vendor 段", () => {
    expect(() => normalizeUploadPath("node_modules/a.js")).toThrow();
    expect(() => normalizeUploadPath("vendor/x.css")).toThrow();
    expect(() => normalizeUploadPath("cgi-bin/x.html")).toThrow();
  });

  it("Windows 保留名与尾随点被拒绝", () => {
    expect(() => normalizeUploadPath("con.html")).toThrow();
    expect(() => normalizeUploadPath("nul.txt")).toThrow();
    expect(() => normalizeUploadPath("name.html.")).toThrow();
    expect(() => normalizeUploadPath("a%2fb.html")).toThrow();
  });

  it("正常文件通过", () => {
    expect(classifyFile("assets/app.final.css").contentType).toMatch(/^text\/css/);
    expect(normalizeUploadPath("docs/index.html")).toBe("docs/index.html");
  });
});

describe("内容签名检查（改后缀绕过）", () => {
  it("ELF / PE / ZIP / WASM 即使伪装成 png/html 也拒绝", () => {
    expect(() => scanContent("png", ELF)).toThrow();
    expect(() => scanContent("html", PE)).toThrow();
    expect(() => scanContent("jpg", ZIP)).toThrow();
    expect(() => scanContent("txt", WASM)).toThrow();
  });

  it("shebang 脚本拒绝", () => {
    expect(() => scanContent("txt", bytes("#!/bin/sh\necho hi"))).toThrow();
  });

  it("图片扩展名必须与魔数一致", () => {
    expect(() => scanContent("png", bytes("<html>not really png</html>"))).toThrow();
    expect(() => scanContent("png", PNG)).not.toThrow();
  });
});

describe("文本内容检查", () => {
  it("服务端标记一律拒绝", () => {
    expect(() => scanContent("html", bytes("<h1>hi</h1><?php echo 1; ?>"))).toThrow();
    expect(() => scanContent("html", bytes("<% code %>"))).toThrow();
    expect(() => scanContent("txt", bytes("<?= $x ?>"))).toThrow();
  });

  it("包含 NUL 的文本拒绝", () => {
    expect(() => scanContent("txt", new Uint8Array([0x68, 0x00, 0x69]))).toThrow();
  });

  it("非 UTF-8 的文本拒绝", () => {
    expect(() => scanContent("html", new Uint8Array([0xff, 0xfe, 0x3c]))).toThrow();
  });

  it("普通 HTML 通过；iframe/object 被拒绝", () => {
    expect(() => scanContent("html", bytes("<!doctype html><h1>hello 你好</h1>"))).not.toThrow();
    expect(() => scanContent("html", bytes("<iframe src=x></iframe>"))).toThrow();
    expect(() => scanContent("htm", bytes("<object data=x></object>"))).toThrow();
  });
});

describe("SVG 净化（拒绝而非修改）", () => {
  it("脚本 / 事件属性 / 外链 / 实体 / foreignObject 均拒绝", () => {
    expect(() => scanContent("svg", bytes('<svg><script>alert(1)</script></svg>'))).toThrow();
    expect(() => scanContent("svg", bytes('<svg onload="alert(1)"></svg>'))).toThrow();
    expect(() => scanContent("svg", bytes('<svg><image href="https://evil.example/x.png"/></svg>'))).toThrow();
    expect(() => scanContent("svg", bytes('<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg>&x;</svg>'))).toThrow();
    expect(() => scanContent("svg", bytes("<svg><foreignObject></foreignObject></svg>"))).toThrow();
    expect(() => scanContent("svg", bytes('<svg><a href="javascript:alert(1)"></a></svg>'))).toThrow();
  });

  it("干净的 SVG 与同文档片段引用通过", () => {
    expect(() =>
      scanContent("svg", bytes('<svg xmlns="http://www.w3.org/2000/svg"><use href="#icon"/><rect width="1" height="1"/></svg>')),
    ).not.toThrow();
  });
});
