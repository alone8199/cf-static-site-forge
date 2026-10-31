/// 路径规范化与防穿越。用户路径只用于展示与匹配 DB 元数据，绝不直接拼接成 存储键。
/// 所有限制（长度、深度、黑名单目录/文件名）均来自 config/app.config.ts。
import { AppError } from "../lib/errors";
import { getConfig } from "../config";

const SEGMENT_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/// Windows 保留设备名（即使带扩展名也危险，如 con.html、nul.txt）
const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])$/i;

function badPath(): AppError {
  return new AppError(400, "invalid_path", "文件路径不合法");
}

/// 规范化上传路径。成功返回形如 "css/app.css" 的相对路径；失败抛出 400。
/// 拒绝：空字节、反斜杠、绝对路径、重复斜杠、"."/".."、隐藏文件/目录、控制字符、
///       非 ASCII、尾随点或空格、Windows 保留名、黑名单目录与文件名、超长、超深。
export function normalizeUploadPath(raw: string): string {
  const up = getConfig().upload;
  const sec = getConfig().security;

  if (typeof raw !== "string" || raw.length === 0 || raw.length > up.maxPathLength) throw badPath();
  // 结构性违规一律拒绝，不做“修复”（修复可能掩盖攻击意图）
  if (raw.includes("\0") || raw.includes("\\")) throw badPath();
  if (raw.startsWith("/") || raw.endsWith("/")) throw badPath();
  if (raw.includes("//")) throw badPath();
  if (/[\u0000-\u001f\u007f]/.test(raw)) throw badPath();
  // 禁止 URL 编码的分隔符，防止解码后绕过
  if (/%2f|%5c|%2e|%00/i.test(raw)) throw badPath();

  const segments = raw.split("/");
  if (segments.length > up.maxPathDepth) throw badPath();

  const blockedDirs = new Set(sec.blockedDirectories.map((d) => d.toLowerCase()));
  for (const seg of segments) {
    if (seg.length === 0 || seg.length > up.maxSegmentLength) throw badPath();
    if (seg === "." || seg === "..") throw badPath();
    if (seg.startsWith(".")) throw badPath(); // 隐藏文件 / 目录
    if (seg.endsWith(".") || seg.endsWith(" ")) throw badPath(); // Windows 尾随点/空格绕过
    if (!SEGMENT_RE.test(seg)) throw badPath();
    const base = seg.split(".")[0] ?? "";
    if (WINDOWS_RESERVED.test(base)) throw badPath();
  }

  // 目录黑名单（除最后一段外的所有段）
  for (const seg of segments.slice(0, -1)) {
    if (blockedDirs.has(seg.toLowerCase())) throw badPath();
  }

  const fileName = segments[segments.length - 1]!.toLowerCase();
  if (sec.blockedFilenames.map((f) => f.toLowerCase()).includes(fileName)) throw badPath();

  return segments.join("/");
}

/// 请求路径（URL pathname）映射到站点内路径。
/// 解码后再次做完整校验，防止 %2e%2e、%5c 等绕过；目录请求映射到 index.html。
export function resolveRequestPath(pathname: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  if (decoded.includes("\0") || decoded.includes("\\")) return null;
  let p = decoded.replace(/^\/+/, "");
  if (p === "" || p.endsWith("/")) p = p + "index.html";
  try {
    return normalizeUploadPath(p);
  } catch {
    return null;
  }
}
