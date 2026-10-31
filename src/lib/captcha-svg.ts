/// 生成带干扰线、噪点、字符抖动的 SVG 验证码图片。
/// 输入的 answer 只用于渲染，不写入任何日志或响应头。
import { randomBytes } from "./crypto";

const COLORS = ["#1f2937", "#374151", "#1e3a8a", "#7c2d12", "#14532d"];

function rnd(max: number): number {
  return randomBytes(2).reduce((acc, b, i) => acc + b * (i ? 256 : 1), 0) % max;
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

export function renderCaptchaSvg(answer: string, seed: string): string {
  const W = 200;
  const H = 70;
  const parts: string[] = [];

  // 干扰线
  for (let i = 0; i < 6; i++) {
    const x1 = rnd(W), y1 = rnd(H), x2 = rnd(W), y2 = rnd(H);
    const c = COLORS[rnd(COLORS.length)];
    parts.push(
      `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${c}" stroke-width="1.5" opacity="0.5"/>`,
    );
  }

  // 字符：逐字符旋转 + 轻微位移
  const step = (W - 30) / answer.length;
  for (let i = 0; i < answer.length; i++) {
    const x = 18 + i * step + rnd(6) - 3;
    const y = 46 + rnd(10) - 5;
    const angle = rnd(30) - 15;
    const c = COLORS[rnd(COLORS.length)];
    parts.push(
      `<text x="${x}" y="${y}" transform="rotate(${angle} ${x} ${y})" font-family="monospace" font-size="34" font-weight="700" fill="${c}">${esc(answer[i]!)}</text>`,
    );
  }

  // 噪点
  for (let i = 0; i < 60; i++) {
    parts.push(
      `<circle cx="${rnd(W)}" cy="${rnd(H)}" r="1" fill="${COLORS[rnd(COLORS.length)]}" opacity="0.4"/>`,
    );
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" data-seed="${esc(seed)}"><rect width="100%" height="100%" fill="#f8fafc"/>${parts.join("")}</svg>`;
}
