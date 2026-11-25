/**
 * 离线生成 PWDSV 服务端 ADMIN_TOKEN 所需的 Argon2id PHC 字符串。
 * 用法：PWDSV_INIT_ADMIN_PWD="xxx" node tools/hash-admin.mjs
 *   或：node tools/hash-admin.mjs "你的管理员密码"
 */
import crypto from "node:crypto";
import { argon2id } from "./extension/src/lib/argon2.js";

const pwd = process.env.PWDSV_INIT_ADMIN_PWD || process.argv[2] || "";
if (pwd.length < 8) {
  console.error("管理员密码至少需要 8 位字符");
  process.exit(1);
}

const salt = crypto.randomBytes(16);
const hash = argon2id(new TextEncoder().encode(pwd), new Uint8Array(salt), {
  iterations: 2,
  memoryKiB: 19456,
  parallelism: 1,
  hashLen: 32,
});
const b64 = (b) => Buffer.from(b).toString("base64").replace(/=+$/g, "");
process.stdout.write(`$argon2id$v=19$m=19456,t=2,p=1$${b64(salt)}$${b64(hash)}`);
