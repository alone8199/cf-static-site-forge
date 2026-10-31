/// 内容级检查：防止“改后缀”绕过。扩展名只是第一道闸门，真正的内容必须也符合类型。
/// 规则全部来自 config/app.config.ts 的 security.content。
///
/// 检查项：
///   1. 文件头签名黑名单（ELF / PE / Mach-O / ZIP / WASM / shebang 等），无论扩展名
///   2. 文本类必须是合法 UTF-8 且不含 NUL（防二进制伪装）
///   3. 服务端标记（<?php、<%、<jsp: 等）一律拒绝
///   4. 图片 / 字体必须与其魔数匹配
///   5. SVG：拒绝脚本、事件属性、外链、实体（XXE）、foreignObject、javascript:
///   6. HTML：拒绝可嵌入外部内容的危险标签（iframe/object/embed 等）
import { AppError } from "../lib/errors";
import { getConfig } from "../config";
import { isTextType } from "./filetypes";

const MAGIC: Record<string, (b: Uint8Array) => boolean> = {
  png: (b) => startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  jpg: (b) => startsWith(b, [0xff, 0xd8, 0xff]),
  jpeg: (b) => startsWith(b, [0xff, 0xd8, 0xff]),
  gif: (b) => startsWith(b, [0x47, 0x49, 0x46, 0x38]), // GIF8
  webp: (b) => startsWith(b, [0x52, 0x49, 0x46, 0x46]) && ascii(b, 8, "WEBP"), // RIFF....WEBP
  ico: (b) => startsWith(b, [0x00, 0x00, 0x01, 0x00]),
  woff: (b) => ascii(b, 0, "wOFF"),
  woff2: (b) => ascii(b, 0, "wOF2"),
  ttf: (b) => startsWith(b, [0x00, 0x01, 0x00, 0x00]) || ascii(b, 0, "true") || ascii(b, 0, "OTTO"),
};

function startsWith(b: Uint8Array, sig: number[]): boolean {
  if (b.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (b[i] !== sig[i]) return false;
  return true;
}

function ascii(b: Uint8Array, offset: number, s: string): boolean {
  if (b.length < offset + s.length) return false;
  for (let i = 0; i < s.length; i++) if (b[offset + i] !== s.charCodeAt(i)) return false;
  return true;
}

function reject(msg: string): never {
  throw new AppError(415, "forbidden_content", msg);
}

export function scanContent(ext: string, bytes: Uint8Array): void {
  const cfg = getConfig().security.content;
  if (!cfg.enabled) return;

  // 1. 文件头黑名单签名（任何扩展名）
  for (const sig of cfg.forbiddenSignatures) {
    if (startsWith(bytes, sig.bytes)) reject("文件内容类型不被允许");
  }

  // 2. 图片 / 字体：魔数必须匹配扩展名
  if (cfg.verifyBinaryMagic && MAGIC[ext] && !isTextType(ext)) {
    if (!MAGIC[ext]!(bytes)) reject("文件内容与扩展名不匹配");
  }

  if (!isTextType(ext)) return;

  // 3. 文本类：不得含 NUL
  if (bytes.includes(0)) reject("文本文件包含非法字节");

  // 4. 必须是合法 UTF-8
  let text: string;
  if (cfg.requireUtf8Text) {
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      reject("文本文件编码必须为 UTF-8");
    }
  } else {
    text = new TextDecoder().decode(bytes);
  }
  const lower = text.toLowerCase();

  // 5. 服务端标记
  for (const marker of cfg.forbiddenMarkers) {
    if (lower.includes(marker.toLowerCase())) reject("文件包含服务端代码标记");
  }

  if (ext === "svg") checkSvg(text, cfg.svg);
  if (ext === "html" || ext === "htm") checkHtml(text, cfg.htmlRejectTags);
}

function checkSvg(
  text: string,
  s: { rejectScripts: boolean; rejectEventHandlers: boolean; rejectExternalRefs: boolean; rejectEntities: boolean; rejectForeignObject: boolean },
): void {
  if (s.rejectScripts && /<\s*script\b/i.test(text)) reject("SVG 不允许包含脚本");
  if (s.rejectEventHandlers && /[\s"'\/]on[a-z]+\s*=/i.test(text)) reject("SVG 不允许包含事件属性");
  if (s.rejectEntities && /<!\s*(doctype|entity)\b/i.test(text)) reject("SVG 不允许包含实体声明");
  if (s.rejectForeignObject && /<\s*foreignobject\b/i.test(text)) reject("SVG 不允许 foreignObject");
  if (/javascript\s*:/i.test(text)) reject("SVG 不允许 javascript: 协议");
  if (s.rejectExternalRefs) {
    // 允许同文档片段引用 (#id)，拒绝任何外部 URL 或 data: 资源
    const ref = /\b(href|src|xlink:href|style)\s*=\s*["']?\s*(https?:|\/\/|data:|url\(\s*["']?(https?:|\/\/|data:))/i;
    if (ref.test(text) || /url\(\s*["']?(https?:|\/\/|data:)/i.test(text)) reject("SVG 不允许外部引用");
  }
}

function checkHtml(text: string, tags: string[]): void {
  if (tags.length === 0) return;
  const re = new RegExp(`<\\s*(${tags.map((t) => t.replace(/[^a-z0-9]/gi, "")).join("|")})\\b`, "i");
  if (re.test(text)) reject("HTML 不允许嵌入该类标签");
}
