/**
 * 加密层自测：直接拿 Bitwarden 官方 SDK 的测试向量核对，
 * 并验证 RSA-OAEP (type 3/4) 组织密钥解包逻辑。
 *
 * 跑法：node test/crypto.test.mjs
 */
import {
  deriveMasterKey, hashMasterPassword, stretchKey, hkdfExpand, encryptBytes, decryptBytes,
  decryptText, SymmetricCryptoKey, bytesToB64, rsaDecrypt, sha256, utf8,
} from "../src/lib/crypto.js";
import { argon2id, blake2b } from "../src/lib/argon2.js";

let pass = 0;
let fail = 0;

function check(name, actual, expected) {
  const a = Array.isArray(actual) ? actual : Array.from(actual);
  const b = Array.isArray(expected) ? expected : Array.from(expected);
  const ok = a.length === b.length && a.every((v, i) => v === b[i]);
  if (ok) {
    pass++;
    console.log("  ok   " + name);
  } else {
    fail++;
    console.error("  FAIL " + name);
    console.error("       期望 " + JSON.stringify(b));
    console.error("       实际 " + JSON.stringify(a));
  }
}

function checkStr(name, actual, expected) {
  if (actual === expected) {
    pass++;
    console.log("  ok   " + name);
  } else {
    fail++;
    console.error("  FAIL " + name + "\n       期望 " + expected + "\n       实际 " + actual);
  }
}

console.log("[1] Blake2b-512 空输入（RFC 7693 附录 A）");
{
  const hex = Array.from(blake2b(new Uint8Array(0), 64), (b) => b.toString(16).padStart(2, "0")).join("");
  checkStr("blake2b(\"\")", hex,
    "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419" +
    "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
}

console.log("[2] PBKDF2 派生 masterKey（官方 SDK test_master_key_derive_pbkdf2）");
{
  const kdf = { kdf: 0, iterations: 10000 };
  const mk = await deriveMasterKey("67t9b5g67$%Dh89n", "test_key", kdf);
  check("PBKDF2 10000 次", mk, [31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129,
    132, 81, 138, 167, 69, 167, 254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75]);
}

console.log("[3] masterPasswordHash 与邮箱大小写/空格归一（官方 test_password_hash_pbkdf2）");
{
  const kdf = { kdf: 0, iterations: 100000 };
  for (const salt of ["test@bitwarden.com", "TEST@bitwarden.com", " test@bitwarden.com"]) {
    const mk = await deriveMasterKey("asdfasdf", salt, kdf);
    const hash = await hashMasterPassword(mk, "asdfasdf");
    checkStr("hash(" + JSON.stringify(salt) + ")", hash, "wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw=");
  }
}

console.log("[4] HKDF-Expand（官方 SDK test_hkdf_expand）");
{
  const prk = new Uint8Array([23, 152, 120, 41, 214, 16, 156, 133, 71, 226, 178, 135, 208, 255, 66,
    101, 189, 70, 173, 30, 39, 215, 175, 236, 38, 180, 180, 62, 196, 4, 159, 70]);
  const out = await hkdfExpand(prk, utf8("info"), 64);
  check("hkdf(prk, \"info\", 64)", out, [6, 114, 42, 38, 87, 231, 30, 109, 30, 255, 104, 129, 255,
    94, 92, 108, 124, 145, 215, 208, 17, 60, 135, 22, 70, 158, 40, 53, 45, 182, 8, 63, 65, 87, 239,
    234, 185, 227, 153, 122, 115, 205, 144, 56, 102, 149, 92, 139, 217, 102, 119, 57, 37, 57, 251,
    178, 18, 52, 94, 77, 132, 215, 239, 100]);
}

console.log("[5] 密钥拉伸 stretchKey（官方 SDK test_stretch_kdf_key）");
{
  const mk = new Uint8Array([31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132,
    81, 138, 167, 69, 167, 254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75]);
  const stretched = await stretchKey(mk);
  check("encKey", stretched.encKey, [111, 31, 178, 45, 238, 152, 37, 114, 143, 215, 124, 83, 135,
    173, 195, 23, 142, 134, 120, 249, 61, 132, 163, 182, 113, 197, 189, 204, 188, 21, 237, 96]);
  check("macKey", stretched.macKey, [221, 127, 206, 234, 101, 27, 202, 38, 86, 52, 34, 28, 78, 28,
    185, 16, 48, 61, 127, 166, 209, 247, 194, 87, 232, 26, 48, 85, 193, 249, 179, 155]);
}

console.log("[6] AES-256-CBC + HMAC-SHA256（官方 SDK test_decrypt_testvector）");
{
  const key = new SymmetricCryptoKey(new Uint8Array(Array.from({ length: 64 }, (_, i) => i)));
  const iv = new Uint8Array([216, 218, 36, 0, 196, 186, 150, 85, 49, 147, 110, 168, 185, 227, 42, 172]);
  const plaintext = new TextEncoder().encode("Bitwarden SDK test vector");
  const aes = await crypto.subtle.importKey("raw", key.encKey, { name: "AES-CBC" }, false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, aes, plaintext));
  const macKey = await crypto.subtle.importKey("raw", key.macKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", macKey, new Uint8Array([...iv, ...ct])));
  check("ciphertext", ct, [234, 77, 16, 15, 189, 82, 36, 188, 182, 88, 64, 67, 145, 94, 30, 178,
    36, 235, 130, 67, 255, 207, 183, 168, 73, 231, 82, 122, 193, 139, 25, 129]);
  check("mac", mac, [60, 78, 44, 111, 72, 233, 3, 6, 86, 250, 217, 242, 62, 229, 184, 221, 231,
    150, 189, 44, 99, 189, 220, 55, 196, 194, 101, 60, 102, 195, 149, 130]);

  const encString = "2." + bytesToB64(iv) + "|" + bytesToB64(ct) + "|" + bytesToB64(mac);
  const back = await decryptText(key, encString);
  checkStr("解密回原文", back, "Bitwarden SDK test vector");

  const round = await decryptText(key, await encryptBytes(key, plaintext));
  checkStr("加密再解密（随机 iv）", round, "Bitwarden SDK test vector");
}

console.log("[7] RSA-OAEP 组织密钥包裹解包（type 4 SHA-1 与 type 3 SHA-256）");
{
  const secret64 = new Uint8Array(Array.from({ length: 64 }, (_, i) => (i * 7 + 3) & 0xff));
  for (const [type, hash] of [[4, "SHA-1"], [3, "SHA-256"]]) {
    const pair = await crypto.subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash },
      true,
      ["encrypt", "decrypt"],
    );
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pair.publicKey, secret64));
    const encStr = `${type}.${bytesToB64(ct)}`;
    const plain = await rsaDecrypt(pkcs8, encStr);
    check(`RSA type ${type} (${hash}) 解包`, plain, secret64);
  }
}

console.log("[8] Argon2id（官方 SDK test_master_key_derive_argon2）");
{
  const t0 = Date.now();
  const salt = await sha256(utf8("test_key"));
  const out = argon2id(utf8("67t9b5g67$%Dh89n"), salt, { iterations: 4, memory: 32, parallelism: 2, hashLen: 32 });
  const ms = Date.now() - t0;
  check("argon2id(t=4, m=32MiB, p=2) 耗时 " + ms + "ms", out, [207, 240, 225, 177, 162, 19, 163,
    76, 98, 106, 179, 175, 224, 9, 17, 240, 20, 147, 237, 47, 246, 150, 141, 184, 62, 225, 131, 242,
    51, 53, 225, 242]);
}

console.log("");
console.log(pass + " 通过, " + fail + " 失败");
process.exit(fail === 0 ? 0 : 1);
