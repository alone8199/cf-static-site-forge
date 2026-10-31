/// 文件类型白名单与黑名单。白名单之外一律拒绝；黑名单用于多段扩展名（如 shell.php.png）。
import { AppError } from "../lib/errors";

export const ALLOWED_EXT: Record<string, string> = {
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
};

/// 明确禁止的可执行 / 服务端文件扩展名（即使出现在多段扩展名中也拒绝）
export const DENIED_EXT = new Set([
  "php", "phtml", "php3", "php4", "php5", "phar", "jsp", "jspx", "asp", "aspx",
  "cgi", "pl", "exe", "dll", "so", "sh", "bash", "bat", "cmd", "ps1", "psm1",
  "py", "pyc", "rb", "go", "wasm", "java", "class", "jar", "war", "msi", "com",
  "scr", "vbs", "htaccess", "htpasswd", "ini", "conf", "env", "lua", "cs",
  "rs", "c", "cpp", "h", "swf", "xap", "dmg", "app", "apk", "deb", "rpm",
]);

export interface FileKind {
  ext: string;
  contentType: string;
}

/// 校验文件名（仅取最后一段）。返回扩展名与 Content-Type。
export function classifyFile(path: string): FileKind {
  const name = path.split("/").pop() ?? "";
  const parts = name.toLowerCase().split(".");
  if (parts.length < 2) {
    throw new AppError(415, "unsupported_file_type", "文件必须带有允许的扩展名");
  }
  for (const p of parts.slice(0, -1)) {
    if (DENIED_EXT.has(p)) {
      throw new AppError(415, "forbidden_file_type", "禁止上传可执行或服务端文件");
    }
  }
  const ext = parts[parts.length - 1]!;
  if (DENIED_EXT.has(ext)) {
    throw new AppError(415, "forbidden_file_type", "禁止上传可执行或服务端文件");
  }
  const contentType = ALLOWED_EXT[ext];
  if (!contentType) {
    throw new AppError(415, "unsupported_file_type", "不支持的文件类型");
  }
  return { ext, contentType };
}
