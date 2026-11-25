/**
 * 端到端协议测试：模拟本仓库 PWDSV 服务端的完整 REST 行为（内存级 fetch 路由，无须受限环境开放端口），
 * 完整走通：预登录 -> 2FA 拦截 -> 登录 -> 同步（含 RSA 组织密钥解包） -> 新建条目 -> 更新密码保留历史 -> 删除。
 *
 * 跑法：node test/e2e.test.mjs
 */
import { PwdsvApi, ApiError, parseTwoFactorProviders } from "../src/lib/api.js";
import {
  deriveMasterKey, hashMasterPassword, encryptText, encryptBytes,
  randomBytes, SymmetricCryptoKey, bytesToB64,
} from "../src/lib/crypto.js";
import { unlockUserKey, decryptSync, buildLoginCipherPayload } from "../src/lib/vault.js";
import { matchesUrl, buildDomainGroups } from "../src/lib/matcher.js";

let pass = 0;
let fail = 0;
function ok(name, cond, extra) {
  if (cond) {
    pass++;
    console.log("  ok   " + name);
  } else {
    fail++;
    console.error("  FAIL " + name + (extra ? "\n       " + JSON.stringify(extra) : ""));
  }
}

/* ------------------------------------------------------------ 假服务端的数据 */
const EMAIL = "me@example.com";
const PASSWORD = "correct horse battery staple";
const KDF_ITER = 10000;
const USER_ID = "11111111-1111-1111-1111-111111111111";
const KEY_ID = "22222222-2222-2222-2222-222222222222";
const ACCESS_TOKEN = "test-access-token";

const masterKey = await deriveMasterKey(PASSWORD, EMAIL, { kdf: 0, iterations: KDF_ITER });
const masterPasswordHash = await hashMasterPassword(masterKey, PASSWORD);
const { userKey } = await unlockUserKey({ key: null }, masterKey);

// 构造真实的 RSA-OAEP 包裹组织密钥，验证老格式组织条目也能解开
const rsaOrg = new SymmetricCryptoKey(randomBytes(64));
const rsaPair = await crypto.subtle.generateKey(
  { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" },
  true,
  ["encrypt", "decrypt"],
);
const pkcs8Bytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", rsaPair.privateKey));
const wrappedOrgKey = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, rsaPair.publicKey, rsaOrg.key));

const folderId = "33333333-3333-3333-3333-333333333333";
const cipher1 = {
  id: "44444444-4444-4444-4444-444444444444",
  type: 1,
  favorite: false,
  folderId,
  organizationId: null,
  revisionDate: "2026-01-01T00:00:00Z",
  name: await encryptText(userKey, "GitHub"),
  notes: await encryptText(userKey, "工作用"),
  login: {
    username: await encryptText(userKey, "octocat"),
    password: await encryptText(userKey, "s3cr3t-pw"),
    totp: await encryptText(userKey, "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"),
    uris: [{ match: null, uri: await encryptText(userKey, "https://github.com/login") }],
  },
};

const ORG_ID = "55555555-5555-5555-5555-555555555555";
const cipher2 = {
  id: "66666666-6666-6666-6666-666666666666",
  type: 1,
  favorite: true,
  folderId: null,
  organizationId: ORG_ID,
  key: null, // 没有 cipher.key，强制走 RSA 组织密钥链路
  revisionDate: "2026-01-02T00:00:00Z",
  name: await encryptText(rsaOrg, "公司内网"),
  notes: null,
  login: {
    username: await encryptText(rsaOrg, "admin"),
    password: await encryptText(rsaOrg, "org-pass"),
    totp: null,
    uris: [{ match: null, uri: await encryptText(rsaOrg, "https://intranet.corp.example") }],
  },
};

const ciphersDb = new Map([
  [cipher1.id, cipher1],
  [cipher2.id, cipher2],
]);
const received = { tokenForms: [] };

function makeResponse(status, obj) {
  const body = obj === null || obj === undefined ? "" : JSON.stringify(obj);
  return {
    ok: status >= 200 && status < 300,
    status,
    async text() {
      return body;
    },
  };
}

async function mockFetch(input, init = {}) {
  const url = new URL(String(input));
  const method = (init.method || "GET").toUpperCase();
  const headers = Object.fromEntries(Object.entries(init.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
  const raw = String(init.body || "");

  if (url.pathname === "/identity/accounts/prelogin" && method === "POST") {
    const body = JSON.parse(raw || "{}");
    if (!body.email) return makeResponse(400, { error: "email is required" });
    return makeResponse(200, {
      kdf: 0,
      kdfIterations: KDF_ITER,
      kdfSettings: { iterations: KDF_ITER, kdfType: 0 },
    });
  }

  if (url.pathname === "/identity/connect/token" && method === "POST") {
    const form = Object.fromEntries(new URLSearchParams(raw));
    received.tokenForms.push(form);

    if (form.grant_type === "refresh_token") {
      return makeResponse(200, { access_token: ACCESS_TOKEN, refresh_token: "refresh-2", expires_in: 3600 });
    }
    for (const k of ["client_id", "password", "scope", "username", "deviceIdentifier", "deviceName", "deviceType"]) {
      if (!form[k]) return makeResponse(400, { error: "invalid_grant", error_description: k + " cannot be blank" });
    }
    if (form.password !== masterPasswordHash) {
      return makeResponse(400, { error: "invalid_grant", error_description: "用户名或密码错误" });
    }
    if (form.twoFactorToken !== "123456") {
      return makeResponse(400, {
        error: "invalid_grant",
        error_description: "Two factor required.",
        TwoFactorProviders: ["0", "1"],
        TwoFactorProviders2: { 0: null, 1: { Email: "m***@example.com" } },
      });
    }
    return makeResponse(200, { access_token: ACCESS_TOKEN, refresh_token: "refresh-1", expires_in: 3600 });
  }

  if (url.pathname === "/api/sync" && method === "GET") {
    if (headers.authorization !== "Bearer " + ACCESS_TOKEN) return makeResponse(401, { error: "unauthorized" });
    return makeResponse(200, {
      object: "sync",
      profile: {
        id: USER_ID,
        email: EMAIL,
        name: "我",
        key: null,
        privateKey: await encryptBytes(userKey, pkcs8Bytes),
        organizations: [{ id: ORG_ID, name: "Acme", key: "4." + bytesToB64(wrappedOrgKey) }],
        securityStamp: "stamp",
      },
      folders: [{ id: folderId, name: await encryptText(userKey, "工作") }],
      collections: [],
      policies: [],
      ciphers: [...ciphersDb.values()],
      domains: { equivalentDomains: [], globalEquivalentDomains: [{ type: 1, domains: ["github.com", "github.dev"], excluded: false }] },
      sends: [],
    });
  }

  if (url.pathname === "/api/ciphers" && method === "POST") {
    if (headers.authorization !== "Bearer " + ACCESS_TOKEN) return makeResponse(401, { error: "unauthorized" });
    const body = JSON.parse(raw || "{}");
    if (body.encryptedFor !== USER_ID) return makeResponse(422, { error: "Invalid user cipher" });
    const created = { ...body, id: "new-cipher-id", revisionDate: "2026-03-01T00:00:00Z" };
    ciphersDb.set(created.id, created);
    return makeResponse(200, created);
  }

  if (url.pathname.startsWith("/api/ciphers/") && method === "PUT") {
    if (headers.authorization !== "Bearer " + ACCESS_TOKEN) return makeResponse(401, { error: "unauthorized" });
    const id = decodeURIComponent(url.pathname.slice("/api/ciphers/".length));
    const body = JSON.parse(raw || "{}");
    const updated = { ...body, id, revisionDate: "2026-03-02T00:00:00Z" };
    ciphersDb.set(id, updated);
    return makeResponse(200, updated);
  }

  if (url.pathname.startsWith("/api/ciphers/") && method === "DELETE") {
    if (headers.authorization !== "Bearer " + ACCESS_TOKEN) return makeResponse(401, { error: "unauthorized" });
    const id = decodeURIComponent(url.pathname.slice("/api/ciphers/".length));
    ciphersDb.delete(id);
    return makeResponse(200, null);
  }

  if (url.pathname === "/api/config") {
    return makeResponse(200, { version: "2.0.0", server: { name: "pwdsv" } });
  }

  return makeResponse(404, { error: "not found" });
}

/* ------------------------------------------------------------------- 跑场景 */
const api = new PwdsvApi("https://vault.local.test", {
  deviceId: "device-abc",
  deviceName: "Chrome 插件",
  fetchImpl: mockFetch,
});

console.log("[1] 预登录拿 KDF 参数");
const kdf = await api.prelogin(EMAIL);
ok("kdf 类型与迭代数", kdf.kdf === 0 && kdf.iterations === KDF_ITER, kdf);

console.log("[2] 登录：先被 2FA 拦下并解析多验证方式");
try {
  await api.login({ email: EMAIL, masterPasswordHash });
  ok("应该要求 2FA", false);
} catch (e) {
  ok("是 ApiError 且 400", e instanceof ApiError && e.status === 400, { status: e.status });
  const twoFactor = parseTwoFactorProviders(e);
  ok("解析出 TOTP 与邮箱两种方式", twoFactor.length === 2 && twoFactor[1].emailHint === "m***@example.com", twoFactor);
}

console.log("[3] 带上 2FA 再登一次");
const tokens = await api.login({ email: EMAIL, masterPasswordHash, twoFactorToken: "123456", twoFactorProvider: 0 });
ok("拿到 access token", tokens.accessToken === ACCESS_TOKEN);
ok("请求体带了 device 信息", received.tokenForms.at(-1).deviceType === "2");

console.log("[4] 密码错了要报清楚");
try {
  await api.login({ email: EMAIL, masterPasswordHash: "wrong", twoFactorToken: "123456" });
  ok("错误密码应该失败", false);
} catch (e) {
  ok("错误密码提示", String(e.message).includes("密码"), e.message);
}

console.log("[5] 同步 + 解密（含 RSA 组织条目）");
const sync = await api.sync(tokens.accessToken);
const { items, folders, domains } = await decryptSync(sync, userKey);
ok("条目数", items.length === 2, items.length);
ok("文件夹解出来了", folders[0].name === "工作", folders);
const gh = items.find((i) => i.name === "GitHub");
ok("名字", gh && gh.name === "GitHub", gh?.name);
ok("用户名", gh && gh.username === "octocat", gh?.username);
ok("密码", gh && gh.password === "s3cr3t-pw", gh?.password);
ok("能匹配 github 等价域名", matchesUrl(gh, "https://github.dev/", { domainGroups: buildDomainGroups(domains) }) === true);

const orgItem = items.find((i) => i.organizationId === ORG_ID);
ok("RSA 组织条目成功解开明文密码", orgItem && orgItem.password === "org-pass", orgItem);

console.log("[6] 新建条目 + 改密更新保留历史密码 + 删除");
const createPayload = await buildLoginCipherPayload(
  { name: "Navicat", username: "root", password: "old-db-password", uris: ["app://navicat.exe"], notes: "本地数据库" },
  { userKey, userId: USER_ID, keyId: KEY_ID },
);
const created = await api.createCipher(tokens.accessToken, createPayload);
const syncAfterCreate = await decryptSync(await api.sync(tokens.accessToken), userKey);
const createdDec = syncAfterCreate.items.find((i) => i.id === created.id);
ok("新建桌面应用条目成功", createdDec?.password === "old-db-password" && createdDec?.uris[0]?.uri === "app://navicat.exe");

const updatePayload = await buildLoginCipherPayload(
  { name: "Navicat", username: "root", password: "new-db-password-2026" },
  { userKey, userId: USER_ID, keyId: KEY_ID, existingItem: createdDec },
);
await api.updateCipher(tokens.accessToken, created.id, updatePayload);
const syncAfterUpdate = await decryptSync(await api.sync(tokens.accessToken), userKey);
const updatedDec = syncAfterUpdate.items.find((i) => i.id === created.id);
ok("更新后拿到新密码", updatedDec?.password === "new-db-password-2026");
ok("旧密码已自动记入 passwordHistory", updatedDec?.passwordHistory?.[0]?.password === "old-db-password", updatedDec?.passwordHistory);
ok("原有的 app:// 规则未丢失", updatedDec?.uris?.[0]?.uri === "app://navicat.exe");

await api.deleteCipher(tokens.accessToken, created.id);
const syncAfterDel = await decryptSync(await api.sync(tokens.accessToken), userKey);
ok("删除后库里不再包含该条目", !syncAfterDel.items.some((i) => i.id === created.id));

console.log("[7] 刷新 token 与探活");
const refreshed = await api.refresh("refresh-1");
ok("刷新拿到新 token", refreshed.accessToken === ACCESS_TOKEN);
const cfg = await api.config();
ok("探活返回版本", cfg.version === "2.0.0");

console.log("");
console.log(pass + " 通过, " + fail + " 失败");
process.exit(fail === 0 ? 0 : 1);
