/// 文件类型判定：扩展名白名单 + 黑名单（任一段命中即拒绝）+ 黑名单文件名。
/// 所有列表来自 config/app.config.ts，可直接修改。
import { AppError } from "../lib/errors";
import { getConfig } from "../config";

export interface FileKind {
  ext: string;
  contentType: string;
}

/// 判定上传文件的类型。失败抛出 415（不泄露具体匹配规则之外的内部细节）。
export function classifyFile(path: string): FileKind {
  const sec = getConfig().security;
  const name = (path.split("/").pop() ?? "").toLowerCase();

  const blockedNames = new Set(sec.blockedFilenames.map((f) => f.toLowerCase()));
  if (blockedNames.has(name)) {
    throw new AppError(415, "forbidden_file_type", "禁止上传该文件");
  }

  const parts = name.split(".");
  if (parts.length < 2 || parts.some((p) => p.length === 0)) {
    throw new AppError(415, "unsupported_file_type", "文件必须带有允许的扩展名");
  }

  // 黑名单：每一段（包括中间段，如 shell.php.png 的 php）都检查
  const blocked = new Set(sec.blockedExtensions.map((e) => e.toLowerCase()));
  for (const p of parts) {
    if (blocked.has(p)) {
      throw new AppError(415, "forbidden_file_type", "禁止上传可执行、服务端或敏感文件");
    }
  }

  const ext = parts[parts.length - 1]!;
  const contentType = sec.allowedExtensions[ext];
  if (!contentType) {
    throw new AppError(415, "unsupported_file_type", "不支持的文件类型");
  }
  return { ext, contentType };
}

export function isTextType(ext: string): boolean {
  return ["html", "htm", "css", "js", "mjs", "json", "txt", "md", "svg"].includes(ext);
}
