/**
 * 密码生成器：随机密码 / PIN。
 * 用 crypto.getRandomValues + 拒绝采样，不用 Math.random。
 */

import { randomBytes } from "./crypto.js";

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/";
// 容易看错的字符（数字 0/1、大写 I/O、竖线、反引号、引号）
const AMBIGUOUS = "IlO01|" + String.fromCharCode(96) + "'\"";

function pick(chars, count, avoidAmbiguous) {
  let pool = chars;
  if (avoidAmbiguous) {
    pool = Array.from(chars).filter((c) => !AMBIGUOUS.includes(c)).join("");
  }
  if (!pool.length) throw new Error("字符池是空的");

  const out = [];
  for (let i = 0; i < count; i++) {
    const limit = 256 - (256 % pool.length); // 去掉 256 除不尽的尾巴，避免取模偏差
    let b;
    do {
      b = randomBytes(1)[0];
    } while (b >= limit);
    out.push(pool[b % pool.length]);
  }
  return out;
}

function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomBytes(1)[0] % (i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

/** 生成随机密码 */
export function generatePassword(opts = {}) {
  const length = Math.max(4, Math.min(128, opts.length ?? 20));
  const useLower = opts.lower !== false;
  const useUpper = opts.upper !== false;
  const useDigits = opts.digits !== false;
  const useSymbols = opts.symbols === true;
  const avoidAmbiguous = opts.avoidAmbiguous !== false;

  const groups = [];
  if (useLower) groups.push(LOWER);
  if (useUpper) groups.push(UPPER);
  if (useDigits) groups.push(DIGITS);
  if (useSymbols) groups.push(SYMBOLS);
  if (!groups.length) groups.push(LOWER);

  const chars = [];
  for (const g of groups) chars.push(...pick(g, 1, avoidAmbiguous)); // 每组至少一个
  const all = groups.join("");
  chars.push(...pick(all, length - chars.length, avoidAmbiguous));
  return shuffle(chars).join("");
}

export function generatePin(length = 6) {
  return pick(DIGITS, Math.max(4, Math.min(32, length)), false).join("");
}

/** 粗估强度：返回 0-4 分和一句人话 */
export function estimateStrength(password) {
  if (!password) return { score: 0, label: "空", entropy: 0 };
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 30;
  const entropy = password.length * Math.log2(pool || 1);
  const score = entropy > 100 ? 4 : entropy > 75 ? 3 : entropy > 55 ? 2 : entropy > 40 ? 1 : 0;
  const label = ["很弱", "弱", "一般", "强", "很强"][score];
  return { score, label, entropy: Math.round(entropy) };
}
