/**
 * Argon2 实现自检：小参数下把 JS 结果和官方实现（argon2-cffi / bitwarden sdk）的对照值比一比。
 * 改了 src/lib/argon2.js 之后先跑这个，比整体跑 crypto.test.mjs 看得更清楚。
 *
 * 跑法：node test/debug_argon2.mjs
 * 对照值是怎么来的：python -c "from argon2.low_level import hash_secret_raw, Type; ..."
 * 注意 argon2-cffi 的 memory 单位是 KiB，而 lib 的 memory 是 MiB，所以这里用 memoryKiB 直接给 KiB。
 */
import { createHash } from "node:crypto";
import { argon2id } from "../src/lib/argon2.js";

const hx = (u) => Buffer.from(u).toString("hex");
const salt = new Uint8Array(createHash("sha256").update("user@example.com").digest());
const pwd = new TextEncoder().encode("password");

const cases = [
  ["t=1 m=64KiB  p=1", { iterations: 1, memoryKiB: 64, parallelism: 1 }, "b4e513a24b7e093cc5269ece3ef106604efea5b207c89d6244891b0ff6bb0234"],
  ["t=3 m=128KiB p=2", { iterations: 3, memoryKiB: 128, parallelism: 2 }, "15574444129a36a1d036fde5883d2dd9cfb98f87e9a43e380e72817296afa00f"],
];

let bad = 0;
for (const [name, opts, expect] of cases) {
  const got = hx(argon2id(pwd, salt, { ...opts, hashLen: 32 }));
  const ok = got === expect;
  console.log((ok ? "ok   " : "FAIL ") + name + "  " + got);
  if (!ok) bad++;
}
process.exit(bad === 0 ? 0 : 1);
