/// 路径规范化与防穿越。用户路径只用于展示与匹配 DB 元数据，绝不直接拼接成 R2 key。
import { AppError } from "../lib/errors";

const MAX_PATH_LEN = 256;
const MAX_DEPTH = 8;
const SEGMENT_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/// 规范化上传路径。成功返回形如 "css/app.css" 的相对路径；失败抛出 400。
/// 拒绝：空字节、反斜杠、绝对路径、重复斜杠、"."/".."、隐藏文件（以 . 开头）、
/// 控制字符、非 ASCII 安全字符、超长、超深。
export function normalizeUploadPath(raw: string): string {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_PATH_LEN) {
    throw badPath();
  }
  // 结构性违规一律拒绝，不做"修复"（修复可能掩盖攻击意图）
  if (raw.includes("\0") || raw.includes("\\") || raw.startsWith("/")) throw badPath();
  if (raw.includes("//")) throw badPath();
  if (/[\u0000-\u001f\u007f]/.test(raw)) throw badPath();
  if (raw.endsWith("/")) throw badPath();

  const segments = raw.split("/");
  if (segments.length > MAX_DEPTH) throw badPath();
  for (const seg of segments) {
    if (seg === "." || seg === "..") throw badPath();
    if (seg.startsWith(".")) throw badPath(); // 隐藏文件 / .htaccess 等
    if (!SEGMENT_RE.test(seg)) throw badPath();
  }
  return segments.join("/");
}

/// 请求路径（URL pathname，已由 URL 解析器处理）映射到站点内路径。
/// 与 normalizeUploadPath 使用同一套规则；目录请求映射到 index.html。
export function resolveRequestPath(pathname: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  // 解码后再次检查，防止 %2e%2e、%5c 等绕过
  if (decoded.includes("\0") || decoded.includes("\\")) return null;
  let p = decoded.replace(/^\/+/, "");
  if (p === "" || p.endsWith("/")) p = p + "index.html";
  try {
    return normalizeUploadPath(p);
  } catch {
    return null;
  }
}

function badPath(): AppError {
  return new AppError(400, "invalid_path", "文件路径不合法");
}
