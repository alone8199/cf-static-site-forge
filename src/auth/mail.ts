/// 邮件发送适配器。
/// - MAIL_MODE=none（默认，生产安全）：不发送任何邮件，验证 token 不会泄露给任何人。
///   此时邮箱无法自助验证，只能通过 BOOTSTRAP_TOKEN 完成管理员初始化（见 routes/bootstrap.ts）。
/// - MAIL_MODE=dev（仅本地开发）：验证 token 通过 API 响应返回，方便调试。切勿在生产启用。
/// - MAIL_MODE=webhook（生产增强项，预留）：POST 到 MAIL_WEBHOOK_URL，由你的邮件服务发送。
import type { Env } from "../env";

export type MailMode = "none" | "dev" | "webhook";

export function mailMode(env: Env): MailMode {
  const m = env.MAIL_MODE;
  return m === "dev" || m === "webhook" ? m : "none";
}

export interface VerificationDelivery {
  /** 仅 dev 模式下返回 token；其余模式为 undefined */
  devToken?: string;
  sent: boolean;
}

export async function deliverVerification(
  env: Env,
  email: string,
  token: string,
): Promise<VerificationDelivery> {
  const mode = mailMode(env);
  if (mode === "dev") {
    return { devToken: token, sent: false };
  }
  if (mode === "webhook" && env.MAIL_WEBHOOK_URL) {
    // 注意：不在日志中输出 token。
    const res = await fetch(env.MAIL_WEBHOOK_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        to: email,
        subject: "验证您的邮箱",
        link: `${env.APP_ORIGIN}/verify-email?token=${encodeURIComponent(token)}`,
      }),
    });
    return { sent: res.ok };
  }
  return { sent: false };
}
