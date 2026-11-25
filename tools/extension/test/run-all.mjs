/**
 * 一把梭跑完所有自测：node test/run-all.mjs
 * 任何一项失败都会以非 0 退出，方便挂到 CI 或 pre-commit 上。
 *
 * 注意：这里用 stdio: "inherit"，子进程直接接终端。
 * 在受限环境里用管道抓子进程输出会被系统拦掉（spawn EPERM），所以别改成 pipe。
 */
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const suites = [
  ["加密层（官方向量）", "crypto.test.mjs"],
  ["工具层（TOTP/匹配/生成）", "util.test.mjs"],
  ["端到端（假服务端）", "e2e.test.mjs"],
  ["后台接线（打桩 chrome）", "background.test.mjs"],
  ["Argon2 小参数对照", "debug_argon2.mjs"],
];

const results = [];
for (const [name, file] of suites) {
  console.log("");
  console.log("================================================================");
  console.log("▶ " + name + "  (" + file + ")");
  console.log("================================================================");
  const res = spawnSync(process.execPath, [path.join(here, file)], { stdio: "inherit" });
  results.push({ name, code: res.status ?? 1 });
}

console.log("");
console.log("=========================== 汇总 ===========================");
let failed = 0;
for (const r of results) {
  const ok = r.code === 0;
  if (!ok) failed++;
  console.log((ok ? "PASS " : "FAIL ") + r.name);
}
process.exit(failed === 0 ? 0 : 1);
