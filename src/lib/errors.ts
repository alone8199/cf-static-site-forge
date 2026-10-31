/// 统一错误类型。对外只返回 code 与安全的 message，绝不包含堆栈、SQL、R2 key 或环境变量。

export class AppError extends Error {
  constructor(
    public readonly status: 400 | 401 | 403 | 404 | 405 | 409 | 413 | 415 | 422 | 429 | 500 | 503,
    public readonly code: string,
    message: string,
    public readonly retryAfter?: number,
  ) {
    super(message);
    this.name = "AppError";
  }
}

export const err = {
  badRequest: (code: string, msg: string) => new AppError(400, code, msg),
  unauthorized: (msg = "请先登录") => new AppError(401, "unauthorized", msg),
  forbidden: (msg = "无权限") => new AppError(403, "forbidden", msg),
  notFound: (msg = "资源不存在") => new AppError(404, "not_found", msg),
  conflict: (code: string, msg: string) => new AppError(409, code, msg),
  tooLarge: (code: string, msg: string) => new AppError(413, code, msg),
  unsupported: (code: string, msg: string) => new AppError(415, code, msg),
  unprocessable: (code: string, msg: string) => new AppError(422, code, msg),
  rateLimited: (retryAfter: number) =>
    new AppError(429, "rate_limited", "请求过于频繁，请稍后再试", retryAfter),
  unavailable: (msg = "服务暂不可用") => new AppError(503, "unavailable", msg),
};

/// 通用错误码：验证码相关统一用同一文案，避免泄露具体失败原因
export const CAPTCHA_FAILED = "验证码错误或已过期";
