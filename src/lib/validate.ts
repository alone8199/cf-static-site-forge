/// 输入校验（zod）。所有外部输入先过这里：长度、类型、格式、枚举。
/// 密码策略与验证码长度读取 config/app.config.ts。
import { z } from "zod";
import { AppError } from "./errors";
import { getConfig } from "../config";

export const EmailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(5)
  .max(254)
  .email("邮箱格式不正确")
  // 拒绝带显示名、引号或空白的形式，避免后续在邮件头中被利用
  .refine((e) => !/[\s<>"'\\]/.test(e), "邮箱格式不正确");

export const PasswordSchema = z.string().superRefine((p, ctx) => {
  const cfg = getConfig().password;
  if (p.length < cfg.minLength) ctx.addIssue({ code: "custom", message: `密码至少 ${cfg.minLength} 位` });
  if (p.length > cfg.maxLength) ctx.addIssue({ code: "custom", message: `密码最多 ${cfg.maxLength} 位` });
  if (cfg.requireLower && !/[a-z]/.test(p)) ctx.addIssue({ code: "custom", message: "密码需包含小写字母" });
  if (cfg.requireUpper && !/[A-Z]/.test(p)) ctx.addIssue({ code: "custom", message: "密码需包含大写字母" });
  if (cfg.requireDigit && !/[0-9]/.test(p)) ctx.addIssue({ code: "custom", message: "密码需包含数字" });
  if (/[\0]/.test(p)) ctx.addIssue({ code: "custom", message: "密码包含非法字符" });
});

export const CaptchaIdSchema = z.string().regex(/^[A-Za-z0-9_-]{16,64}$/, "验证码 ID 无效");

export const CaptchaAnswerSchema = z
  .string()
  .trim()
  .min(1)
  .max(8)
  .regex(/^[A-Za-z0-9]+$/, "验证码格式无效")
  .transform((s) => s.toUpperCase());

export const SiteNameSchema = z
  .string()
  .trim()
  .min(1, "站点名称不能为空")
  .max(80, "站点名称最多 80 字符")
  // 禁止控制字符，防止日志与界面注入
  .refine((s) => !/[\u0000-\u001f\u007f]/.test(s), "站点名称包含非法字符");

export const IdParamSchema = z.string().regex(/^[a-f0-9]{32}$/, "ID 格式无效");

export const TokenSchema = z.string().regex(/^[A-Za-z0-9_-]{20,128}$/, "令牌格式无效");

export function parseOrThrow<T extends z.ZodTypeAny>(schema: T, input: unknown): z.infer<T> {
  const result = schema.safeParse(input);
  if (!result.success) {
    throw new AppError(400, "validation_error", result.error.issues[0]?.message ?? "输入无效");
  }
  return result.data;
}
