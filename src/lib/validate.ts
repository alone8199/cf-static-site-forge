/// 输入校验（zod）。所有外部输入先过这里：长度、类型、格式、枚举。
import { z } from "zod";
import { AppError } from "./errors";

export const EmailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(5)
  .max(254)
  .email("邮箱格式不正确");

/// 密码强度：10-128 位，需同时包含大小写字母与数字。
export const PasswordSchema = z
  .string()
  .min(10, "密码至少 10 位")
  .max(128, "密码最多 128 位")
  .refine((p) => /[a-z]/.test(p), "密码需包含小写字母")
  .refine((p) => /[A-Z]/.test(p), "密码需包含大写字母")
  .refine((p) => /[0-9]/.test(p), "密码需包含数字");

export const CaptchaIdSchema = z.string().regex(/^[A-Za-z0-9_-]{16,64}$/, "验证码 ID 无效");

export const CaptchaAnswerSchema = z
  .string()
  .trim()
  .min(1)
  .max(8)
  .regex(/^[A-Za-z0-9]+$/, "验证码格式无效")
  .transform((s) => s.toUpperCase());

export const SiteNameSchema = z.string().trim().min(1, "站点名称不能为空").max(80, "站点名称最多 80 字符");

export const IdParamSchema = z.string().regex(/^[a-f0-9]{32}$/, "ID 格式无效");

export const UuidSchema = z.string().regex(/^[0-9a-f-]{36}$/, "ID 格式无效");

export const TokenSchema = z.string().regex(/^[A-Za-z0-9_-]{20,128}$/, "令牌格式无效");

export function parseOrThrow<T extends z.ZodTypeAny>(
  schema: T,
  input: unknown,
): z.infer<T> {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new AppError(400, "validation_error", result.error.issues[0]?.message ?? "输入无效");
  }
  return result.data;
}
