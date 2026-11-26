/**
 * PWDSV 浏览器插件 —— 加密原语
 *
 * 这一层必须和 Bitwarden / PWDSV 服务端逐字节一致，否则库里所有密文都解不开。
 * 参照实现（bitwarden/sdk-internal 里的 bitwarden-crypto）：
 *
 *   masterKey          = PBKDF2-SHA256(password, lower(trim(email)), kdfIterations, 32B)
 *                      | Argon2id(password, SHA256(lower(trim(email))), t, m MiB, p, 32B)
 *   masterPasswordHash = PBKDF2-SHA256(masterKey, password, 1, 32B) -> base64（登录时当密码发）
 *   stretchedKey       = HKDF-Expand-SHA256(masterKey, "enc" | "mac", 32B) 拼成 64B
 *                        前 32B 是 AES-256-CBC 的钥匙，后 32B 是 HMAC-SHA256 的钥匙
 *   EncString          = "2.<iv>|<ciphertext>|<mac>"（iv 16B，mac 32B，AES-256-CBC + PKCS7）
 *                        mac = HMAC-SHA256(macKey, iv || ciphertext)
 *
 * 老数据的 "0.iv|ct" 是不带 MAC 的 Aes256Cbc，也一并支持。
 * RSA 密文形如 "3.<ct>" / "4.<ct>"（无 iv）或 "5.<ct>|<mac>" / "6.<ct>|<mac>"。
 */

import { argon2id } from "./argon2.js";

const TE = new TextEncoder();
const TD = new TextDecoder();

export const KdfType = Object.freeze({ Pbkdf2: 0, Argon2id: 1 });
export const EncType = Object.freeze({
  AesCbc256: 0,                    // 2.0 时代的老格式，没有 MAC
  AesCbc128HmacSha256: 1,          // 早期 128 位格式
  AesCbc256HmacSha256: 2,          // 现在的主流对称格式
  Rsa2048OaepSha256: 3,            // RSA-OAEP-SHA256 包裹密钥
  Rsa2048OaepSha1: 4,              // RSA-OAEP-SHA1 包裹密钥
  Rsa2048OaepSha256HmacSha256: 5,  // RSA-OAEP-SHA256 + HMAC
  Rsa2048OaepSha1HmacSha256: 6,    // RSA-OAEP-SHA1 + HMAC
  CoseEncrypt0: 7,                 // 2025 之后的新格式，本插件不处理
});

const RSA_ENC_TYPES = new Set([
  EncType.Rsa2048OaepSha256,
  EncType.Rsa2048OaepSha1,
  EncType.Rsa2048OaepSha256HmacSha256,
  EncType.Rsa2048OaepSha1HmacSha256,
]);

export function isRsaEncType(type) {
  return RSA_ENC_TYPES.has(Number(type));
}

/* ------------------------------------------------------------------ 字节工具 */

export const utf8 = (s) => TE.encode(s);
export const fromUtf8 = (b) => TD.decode(b);

export function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function bytesToB64(bytes) {
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

export function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/* -------------------------------------------------------------- 基础密码学运算 */

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

export async function pbkdf2(passwordBytes, saltBytes, iterations, dkLen = 32, hash = "SHA-256") {
  const key = await crypto.subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash, salt: saltBytes, iterations },
    key,
    dkLen * 8,
  );
  return new Uint8Array(bits);
}

export async function hmac(hashName, keyBytes, dataBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: hashName },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, dataBytes));
}

/** RFC 5869 的 HKDF-Expand（只 Expand 不 Extract，Bitwarden 就是这么用的） */
export async function hkdfExpand(prk, info, length = 32) {
  const out = new Uint8Array(length);
  let prev = new Uint8Array(0);
  let pos = 0;
  for (let counter = 1; pos < length; counter++) {
    const input = concatBytes(prev, info, new Uint8Array([counter]));
    prev = await hmac("SHA-256", prk, input);
    const take = Math.min(prev.length, length - pos);
    out.set(prev.subarray(0, take), pos);
    pos += take;
  }
  return out;
}

/* ------------------------------------------------------------------- 主密钥派生 */

/**
 * 由主密码派生 32 字节 masterKey。
 * @param {string} password
 * @param {string} email
 * @param {{kdf:number, iterations?:number, memory?:number, parallelism?:number}} kdf prelogin 返回的参数
 */
export async function deriveMasterKey(password, email, kdf) {
  const salt = utf8(String(email || "").trim().toLowerCase());
  const type = Number(kdf?.kdf ?? KdfType.Pbkdf2);

  if (type === KdfType.Argon2id) {
    const iterations = Number(kdf.iterations ?? 3);
    const memory = Number(kdf.memory ?? 64);        // 单位 MiB
    const parallelism = Number(kdf.parallelism ?? 4);
    const argonSalt = await sha256(salt);           // Argon2 的盐是邮箱的 SHA-256
    return argon2id(utf8(password), argonSalt, {
      iterations,
      memory,
      parallelism,
      hashLen: 32,
    });
  }

  const iterations = Number(kdf?.iterations ?? 600000);
  return pbkdf2(utf8(password), salt, iterations, 32);
}

/** 发给服务端的 masterPasswordHash：PBKDF2(masterKey, password, 1) 的 base64 */
export async function hashMasterPassword(masterKey, password) {
  const hash = await pbkdf2(masterKey, utf8(password), 1, 32);
  return bytesToB64(hash);
}

/* ------------------------------------------------------------------ 对称密钥对象 */

export class SymmetricCryptoKey {
  /** @param {Uint8Array} bytes 32 字节（只有 AES）或 64 字节（AES + MAC） */
  constructor(bytes) {
    if (bytes.length !== 32 && bytes.length !== 64) {
      throw new Error("对称密钥长度必须是 32 或 64 字节，拿到的是 " + bytes.length);
    }
    this.key = bytes;
    this.encKey = bytes.subarray(0, 32);
    this.macKey = bytes.length === 64 ? bytes.subarray(32, 64) : null;
  }

  static fromB64(b64) {
    return new SymmetricCryptoKey(b64ToBytes(b64));
  }

  toB64() {
    return bytesToB64(this.key);
  }
}

/** 32 字节 masterKey 拉伸成 64 字节（enc + mac） */
export async function stretchKey(masterKey) {
  const encKey = await hkdfExpand(masterKey, utf8("enc"), 32);
  const macKey = await hkdfExpand(masterKey, utf8("mac"), 32);
  return new SymmetricCryptoKey(concatBytes(encKey, macKey));
}

/** 由解密出来的字节还原对称密钥：32B 是 AES-only，64B 是 AES+MAC */
export function keyFromBytes(bytes) {
  if (bytes.length === 32 || bytes.length === 64) return new SymmetricCryptoKey(bytes);
  if (bytes.length > 32) return new SymmetricCryptoKey(bytes.subarray(0, 64));
  throw new Error("无法识别的密钥长度：" + bytes.length);
}

/* --------------------------------------------------------------------- EncString */

export function parseEncString(input) {
  if (typeof input !== "string") throw new Error("密文不是字符串");
  const dot = input.indexOf(".");
  if (dot < 0) {
    // 老的无头格式：三段当作 1（Aes128，已废弃），两段当作 0
    const parts = input.split("|");
    if (parts.length === 3) return { type: 1, iv: parts[0], data: parts[1], mac: parts[2] };
    if (parts.length === 2) {
      return { type: EncType.AesCbc256, iv: parts[0], data: parts[1], mac: null };
    }
    throw new Error("无法解析的密文格式");
  }
  const type = Number(input.slice(0, dot));
  const rest = input.slice(dot + 1);
  if (type === EncType.CoseEncrypt0) {
    return { type, cose: rest, iv: null, data: rest, mac: null };
  }
  const parts = rest.split("|");
  // RSA 密文没有 IV，形如 "4.<ct>" 或 "6.<ct>|<mac>"
  if (isRsaEncType(type)) {
    return { type, iv: null, data: parts[0] ?? null, mac: parts[1] ?? null };
  }
  return { type, iv: parts[0] ?? null, data: parts[1] ?? null, mac: parts[2] ?? null };
}

async function importAesKey(keyBytes) {
  return crypto.subtle.importKey("raw", keyBytes, { name: "AES-CBC" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** 加密一段字节，产出 "2.iv|ct|mac" */
export async function encryptBytes(key, plaintext) {
  if (!(key instanceof SymmetricCryptoKey)) key = keyFromBytes(key);
  if (!key.macKey) throw new Error("加密需要 64 字节复合密钥");
  const iv = randomBytes(16);
  const aes = await importAesKey(key.encKey);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aes, plaintext));
  const mac = await hmac("SHA-256", key.macKey, concatBytes(iv, ct));
  return "2." + bytesToB64(iv) + "|" + bytesToB64(ct) + "|" + bytesToB64(mac);
}

export async function encryptText(key, text) {
  return encryptBytes(key, utf8(text));
}

/** 解密 "2.iv|ct|mac" / "0.iv|ct"，返回字节 */
export async function decryptBytes(key, encString) {
  if (!(key instanceof SymmetricCryptoKey)) key = keyFromBytes(key);
  const parsed = parseEncString(encString);

  if (parsed.type === EncType.CoseEncrypt0) {
    throw new Error("COSE_B64 加密格式（type 7）暂不支持，请用官方客户端查看该条目");
  }
  if (parsed.type !== EncType.AesCbc256 && parsed.type !== EncType.AesCbc256HmacSha256) {
    throw new Error("不支持的密文类型：" + parsed.type);
  }

  const iv = b64ToBytes(parsed.iv);
  const data = b64ToBytes(parsed.data);

  if (parsed.type === EncType.AesCbc256HmacSha256) {
    if (!key.macKey) throw new Error("缺少 MAC 密钥");
    const expected = b64ToBytes(parsed.mac || "");
    const actual = await hmac("SHA-256", key.macKey, concatBytes(iv, data));
    if (!constantTimeEqual(expected, actual)) {
      throw new Error("MAC 校验失败：密钥不对，或者数据被改过");
    }
  }

  const aes = await importAesKey(key.encKey);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv }, aes, data));
}

export async function decryptText(key, encString) {
  return fromUtf8(await decryptBytes(key, encString));
}

/* --------------------------------------------------------------------- RSA 相关 */

/**
 * 用 RSA 私钥解一段 type 3/4/5/6 密文（组织密钥等都是这么包的）。
 * type 3/5 用 OAEP + SHA-256，type 4/6 用 OAEP + SHA-1，失败时自动兜底另一种哈希。
 */
export async function rsaDecrypt(privateKeyPkcs8, encString) {
  const parsed = parseEncString(encString);
  if (!isRsaEncType(parsed.type)) {
    throw new Error("不是 RSA 密文（type=" + parsed.type + "）");
  }
  if (!parsed.data) {
    throw new Error("RSA 密文内容为空");
  }
  const data = b64ToBytes(parsed.data);
  const preferSha256 =
    parsed.type === EncType.Rsa2048OaepSha256 ||
    parsed.type === EncType.Rsa2048OaepSha256HmacSha256;
  const order = preferSha256 ? ["SHA-256", "SHA-1"] : ["SHA-1", "SHA-256"];

  let lastErr = null;
  for (const hash of order) {
    try {
      const k = await crypto.subtle.importKey(
        "pkcs8",
        privateKeyPkcs8,
        { name: "RSA-OAEP", hash },
        false,
        ["decrypt"],
      );
      return new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, k, data));
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error("RSA 解密失败");
}

/** 解出账户私钥（profile.privateKey 是对称加密的 PKCS8 DER），返回字节 */
export async function decryptPrivateKey(userKey, encPrivateKey) {
  if (!encPrivateKey) return null;
  const parsed = parseEncString(encPrivateKey);
  if (isRsaEncType(parsed.type)) {
    throw new Error("账户私钥被 RSA 包着，这里没法自解");
  }
  return decryptBytes(userKey, encPrivateKey);
}

/**
 * 零知识本地注册：派生 masterKey / masterPasswordHash，生成随机 64B userKey 与 RSA-2048 密钥对，
 * 产出可直接提交至 POST /identity/accounts/register 的请求体（原始主密码永不离开本机）。
 */
export async function makeRegisterPayload({
  email,
  password,
  name = "",
  masterPasswordHint = "",
  kdfIterations = 600000,
}) {
  const normEmail = String(email || "").trim().toLowerCase();
  if (!normEmail) throw new Error("请填写有效的账号邮箱");
  if (String(password || "").length < 8) throw new Error("主密码长度至少 8 位");

  const iterations = Number(kdfIterations) || 600000;
  const masterKey = await deriveMasterKey(password, normEmail, { kdf: KdfType.Pbkdf2, iterations });
  const masterPasswordHash = await hashMasterPassword(masterKey, password);
  const stretched = await stretchKey(masterKey);

  const userKeyBytes = randomBytes(64);
  const userKey = new SymmetricCryptoKey(userKeyBytes);
  const key = await encryptBytes(stretched, userKeyBytes);

  const rsaPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-1",
    },
    true,
    ["encrypt", "decrypt"],
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", rsaPair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", rsaPair.privateKey));
  const publicKey = bytesToB64(spki);
  const encryptedPrivateKey = await encryptBytes(userKey, pkcs8);

  return {
    email: normEmail,
    name: name ? String(name).trim().slice(0, 50) : null,
    masterPasswordHash,
    masterPasswordHint: masterPasswordHint ? String(masterPasswordHint).trim() : null,
    key,
    kdf: KdfType.Pbkdf2,
    kdfIterations: iterations,
    keys: { publicKey, encryptedPrivateKey },
  };
}
