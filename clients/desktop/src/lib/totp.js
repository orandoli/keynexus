/**
 * TOTP 生成（RFC 6238），以及 otpauth:// 解析。
 *
 * 库里 totp 字段解密出来要么是 otpauth://totp/...?secret=XXX，要么是裸 base32 密钥，
 * 两种都支持。默认 6 位、30 秒、SHA-1，和 Google Authenticator 一致。
 */

import { hmac } from "./crypto.js";

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** base32 解码（不区分大小写，容忍空格、- 和 = 填充） */
export function base32Decode(input) {
  const clean = String(input || "").toUpperCase().replace(/[\s\-=]/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error("base32 里有非法字符：" + ch);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** 解析 otpauth:// URI 或裸密钥 */
export function parseTotp(raw) {
  const text = String(raw || "").trim();
  if (!text) throw new Error("空的 TOTP 配置");

  if (!/^otpauth:\/\//i.test(text)) {
    return { secret: text, digits: 6, period: 30, algorithm: "SHA-1", issuer: "", account: "" };
  }

  const url = new URL(text.replace(/^otpauth:\/\//i, "https://"));
  const params = url.searchParams;
  const secret = params.get("secret");
  if (!secret) throw new Error("otpauth 里没有 secret");

  const algorithmRaw = (params.get("algorithm") || "SHA1").toUpperCase().replace(/-/g, "");
  const algorithm =
    algorithmRaw === "SHA256" ? "SHA-256" : algorithmRaw === "SHA512" ? "SHA-512" : "SHA-1";

  const label = decodeURIComponent(url.pathname.replace(/^\//, ""));
  const [labelIssuer, account] = label.includes(":") ? label.split(/:(.+)/) : ["", label];

  return {
    secret,
    digits: Number(params.get("digits") || 6),
    period: Number(params.get("period") || 30),
    algorithm,
    issuer: params.get("issuer") || labelIssuer.trim(),
    account: (account || "").trim(),
  };
}

/**
 * 生成验证码。
 * @param {string} raw otpauth URI 或 base32 密钥
 * @param {number} [now] 毫秒时间戳，测试用
 */
export async function generateTotp(raw, now = Date.now()) {
  const cfg = parseTotp(raw);
  const key = base32Decode(cfg.secret);
  const counter = Math.floor(now / 1000 / cfg.period);

  // 计数器按大端 8 字节
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 0xff;
    c = Math.floor(c / 256);
  }

  const digest = await hmac(cfg.algorithm, key, msg);
  const offset = digest[digest.length - 1] & 0x0f;
  const bin =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  const code = String(bin % 10 ** cfg.digits).padStart(cfg.digits, "0");
  const elapsed = (now / 1000) % cfg.period;
  return {
    code,
    remaining: Math.ceil(cfg.period - elapsed),
    period: cfg.period,
    digits: cfg.digits,
  };
}

/** 判断输入框像不像验证码框（沿用油猴脚本那套选择器思路） */
export const OTP_FIELD_SELECTORS = [
  'input[autocomplete="one-time-code"]',
  'input[name*="totp" i]',
  'input[name*="otp" i]',
  'input[name*="mfa" i]',
  'input[name*="2fa" i]',
  'input[name*="verification" i]',
  'input[name*="passcode" i]',
  'input[name*="auth_code" i]',
  'input[name*="security_code" i]',
  'input[name*="two_factor" i]',
  'input[id*="otp" i]',
  'input[id*="totp" i]',
  'input[id*="2fa" i]',
  'input[id*="two-factor" i]',
  'input[id*="mfa" i]',
  'input[placeholder*="验证码"]',
  'input[placeholder*="安全码"]',
  'input[placeholder*="动态口令"]',
  'input[placeholder*="verification" i]',
  'input[placeholder*="one-time" i]',
  'input[placeholder*="6-digit" i]',
  'input[placeholder*="auth code" i]',
  'input[aria-label*="verification" i]',
  'input[aria-label*="one-time" i]',
  'input[data-testid*="otp" i]',
  'input[data-testid*="totp" i]',
  'input[inputmode="numeric"][maxlength="6"]',
];
