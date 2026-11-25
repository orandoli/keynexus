/**
 * 后台（service worker）接线测试 v2.0：
 * 打桩 chrome.* 并注入内存级 fetch + WebSocket，验证完整业务闭环：
 * 1. 解锁与 2FA
 * 2. 当前站点筛选 vs 跨站点全库搜索 vs 桌面应用筛选
 * 3. TOTP 动态码与倒计时秒数
 * 4. 分步登录跨页面抓密（第 1 页暂存账号 -> 第 2 页提交密码 -> 落地页弹出保存/更新）
 * 5. 手动提交新密码 / 编辑更新密码 / 删除密码
 * 6. 跨域恶意 iframe 自动填充拦截
 * 7. WebSocket /notifications/hub 服务端推送自动同步
 *
 * 跑法：node test/background.test.mjs
 */

/* ------------------------------------------------------------------ chrome 打桩 */
const localStore = new Map();
const sessionStore = new Map();
const listeners = { message: null, command: null, alarm: null, installed: null, menu: null };

function area(store) {
  return {
    async get(key) {
      if (key === undefined || key === null) return Object.fromEntries(store);
      const keys = Array.isArray(key) ? key : [key];
      const out = {};
      for (const k of keys) if (store.has(k)) out[k] = structuredClone(store.get(k));
      return out;
    },
    async set(patch) {
      for (const [k, v] of Object.entries(patch)) store.set(k, structuredClone(v));
    },
    async remove(key) {
      for (const k of Array.isArray(key) ? key : [key]) store.delete(k);
    },
    async clear() {
      store.clear();
    },
  };
}

globalThis.chrome = {
  storage: { local: area(localStore), session: area(sessionStore) },
  runtime: {
    onMessage: { addListener: (fn) => (listeners.message = fn) },
    onInstalled: { addListener: (fn) => (listeners.installed = fn) },
    lastError: null,
    getManifest: () => ({ version: "2.0.0" }),
  },
  commands: { onCommand: { addListener: (fn) => (listeners.command = fn) } },
  contextMenus: {
    removeAll: (cb) => cb?.(),
    create() {},
    onClicked: { addListener: (fn) => (listeners.menu = fn) },
  },
  alarms: { create() {}, onAlarm: { addListener: (fn) => (listeners.alarm = fn) } },
  tabs: { query: async () => [], sendMessage: async () => {} },
};

/* ----------------------------------------------------- 假 WebSocket 与假服务端 */
const wsInstances = [];
class MockWebSocket {
  constructor(url) {
    this.url = url;
    this.readyState = 0;
    this.sent = [];
    this.handlers = {};
    wsInstances.push(this);
    queueMicrotask(() => {
      this.readyState = 1;
      this.emit("open", {});
    });
  }
  addEventListener(type, fn) {
    (this.handlers[type] ||= []).push(fn);
  }
  send(data) {
    this.sent.push(data);
  }
  close() {
    this.readyState = 3;
    this.emit("close", {});
  }
  emit(type, ev) {
    for (const fn of this.handlers[type] || []) fn(ev);
  }
}

const EMAIL = "me@example.com";
const PASSWORD = "correct horse battery staple";
const ITER = 10000;
const USER_ID = "11111111-1111-1111-1111-111111111111";
const KEY_ID = "22222222-2222-2222-2222-222222222222";
const TOKEN = "tok";

const {
  deriveMasterKey, hashMasterPassword, encryptText, encryptBytes, stretchKey, randomBytes, SymmetricCryptoKey,
} = await import("../src/lib/crypto.js");

const masterKey = await deriveMasterKey(PASSWORD, EMAIL, { kdf: 0, iterations: ITER });
const passwordHash = await hashMasterPassword(masterKey, PASSWORD);
const stretched = await stretchKey(masterKey);
const userKey = new SymmetricCryptoKey(randomBytes(64));

const ciphersDb = new Map();
const baseCipher = {
  id: "44444444-4444-4444-4444-444444444444",
  type: 1,
  favorite: false,
  folderId: null,
  organizationId: null,
  revisionDate: "2026-01-01T00:00:00Z",
  name: await encryptText(userKey, "GitHub"),
  notes: null,
  login: {
    username: await encryptText(userKey, "octocat"),
    password: await encryptText(userKey, "s3cr3t-pw"),
    totp: await encryptText(userKey, "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"),
    uris: [{ match: null, uri: await encryptText(userKey, "https://github.com/login") }],
  },
};
ciphersDb.set(baseCipher.id, baseCipher);

let idSeq = 1;
function makeRes(status, obj) {
  const body = obj === null || obj === undefined ? "" : JSON.stringify(obj);
  return { ok: status >= 200 && status < 300, status, async text() { return body; } };
}

async function mockFetch(input, init = {}) {
  const url = new URL(String(input));
  const method = (init.method || "GET").toUpperCase();
  const headers = Object.fromEntries(Object.entries(init.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
  const raw = String(init.body || "");

  if (url.pathname === "/identity/accounts/prelogin") {
    return makeRes(200, { kdf: 0, kdfIterations: ITER, kdfSettings: { iterations: ITER, kdfType: 0 } });
  }
  if (url.pathname === "/identity/connect/token") {
    const form = Object.fromEntries(new URLSearchParams(raw));
    if (form.grant_type === "refresh_token") {
      return makeRes(200, { access_token: TOKEN, refresh_token: "r2", expires_in: 3600 });
    }
    if (form.password !== passwordHash) return makeRes(400, { error: "invalid_grant", error_description: "用户名或密码错误" });
    if (form.twoFactorToken !== "654321") {
      return makeRes(400, { error: "invalid_grant", TwoFactorProviders: ["0"], TwoFactorProviders2: { 0: null } });
    }
    return makeRes(200, { access_token: TOKEN, refresh_token: "r1", expires_in: 3600 });
  }
  if (url.pathname === "/api/sync") {
    if (headers.authorization !== "Bearer " + TOKEN) return makeRes(401, { error: "unauthorized" });
    return makeRes(200, {
      object: "sync",
      profile: {
        id: USER_ID,
        email: EMAIL,
        key: await encryptBytes(stretched, userKey.key),
        privateKey: null,
        organizations: [],
        securityStamp: "s",
      },
      folders: [],
      collections: [],
      policies: [],
      ciphers: [...ciphersDb.values()],
      domains: { equivalentDomains: [], globalEquivalentDomains: [] },
      sends: [],
      userDecryption: { userKeyId: KEY_ID },
    });
  }
  if (url.pathname === "/api/ciphers" && method === "POST") {
    if (headers.authorization !== "Bearer " + TOKEN) return makeRes(401, { error: "unauthorized" });
    const body = JSON.parse(raw);
    if (body.encryptedFor !== USER_ID) return makeRes(422, { error: "Invalid user cipher" });
    const created = { ...body, id: "new-" + (idSeq++), revisionDate: "2026-02-01T00:00:00Z" };
    ciphersDb.set(created.id, created);
    return makeRes(200, created);
  }
  if (url.pathname.startsWith("/api/ciphers/") && method === "PUT") {
    if (headers.authorization !== "Bearer " + TOKEN) return makeRes(401, { error: "unauthorized" });
    const id = decodeURIComponent(url.pathname.slice("/api/ciphers/".length));
    const body = JSON.parse(raw);
    const updated = { ...body, id, revisionDate: "2026-02-02T00:00:00Z" };
    ciphersDb.set(id, updated);
    return makeRes(200, updated);
  }
  if (url.pathname.startsWith("/api/ciphers/") && method === "DELETE") {
    if (headers.authorization !== "Bearer " + TOKEN) return makeRes(401, { error: "unauthorized" });
    const id = decodeURIComponent(url.pathname.slice("/api/ciphers/".length));
    ciphersDb.delete(id);
    return makeRes(200, null);
  }
  if (url.pathname === "/api/config") return makeRes(200, { version: "2.0.0" });
  return makeRes(404, { error: "not found" });
}

/* ---------------------------------------------------------------------- 跑起来 */
const bg = await import("../src/background.js");
bg.__setTestTransports({ fetchImpl: mockFetch, WebSocketImpl: MockWebSocket });

if (!listeners.message) throw new Error("后台没有注册 onMessage");

function call(msg, sender = {}) {
  return new Promise((resolve) => {
    const ret = listeners.message(msg, sender, resolve);
    if (ret === false) resolve(undefined);
  });
}

let pass = 0;
let fail = 0;
function ok(name, cond, extra) {
  if (cond) {
    pass++;
    console.log("  ok   " + name);
  } else {
    fail++;
    console.error("  FAIL " + name + (extra !== undefined ? "  " + JSON.stringify(extra) : ""));
  }
}

const baseUrl = "https://pwdsv.local.test";

console.log("[1] 初始状态是锁着的");
const st0 = await call({ type: "status" });
ok("locked", st0.locked === true);

console.log("[2] 解锁：先被 2FA 拦下，再带验证码解锁并连上实时 WebSocket");
const r1 = await call({ type: "unlock", serverUrl: baseUrl, email: EMAIL, password: PASSWORD });
ok("要求两步验证", r1.needsTwoFactor === true, r1);
ok("带上可用方式", Array.isArray(r1.providers) && r1.providers[0].id === 0, r1.providers);

const r2 = await call({ type: "unlock", serverUrl: baseUrl, email: EMAIL, password: PASSWORD, twoFactorToken: "654321", twoFactorProvider: 0 });
ok("解锁成功", r2.ok === true && r2.itemCount === 1, r2);
await new Promise((r) => setTimeout(r, 10));
ok("实时 WebSocket 已建立并发送 SignalR 握手帧", wsInstances.length === 1 && String(wsInstances[0].sent[0]).includes("messagepack"));

console.log("[3] 列表、跨站点全局搜索（修复旧版搜索被当前网址锁死的问题）");
const byOtherSite = await call({ type: "list", url: "https://google.com/" });
ok("在无关站点看『当前网站』为 0 条，但返回全库总数 1", byOtherSite.items.length === 0 && byOtherSite.total === 1);

const globalSearchOnOtherSite = await call({ type: "list", url: "https://google.com/", query: "github" });
ok("在 google.com 搜索 github 依然能从全库搜出来", globalSearchOnOtherSite.items.length === 1 && globalSearchOnOtherSite.items[0].name === "GitHub");

console.log("[4] TOTP 取码与倒计时秒数、跨域恶意 iframe 拦截");
const totp = await call({ type: "secret", id: baseCipher.id, field: "totp" });
ok("TOTP 是 6 位数字且带倒计时秒数", /^\d{6}$/.test(totp.value) && totp.remaining > 0 && totp.remaining <= 30, totp);

const evilFrameFill = await call(
  { type: "fillData", id: baseCipher.id, url: "https://github.com/login" },
  { tab: { id: 9 }, url: "https://evil-phishing.example/iframe" },
);
ok("跨域恶意 iframe 伪造 url 被后台拦截", Boolean(evilFrameFill.error), evilFrameFill);

console.log("[5] 两步登录 + 页面跳转后的抓密暂存池与改密自动识别");
const tabSender = { tab: { id: 42 }, url: "https://github.com/login" };
await call({ type: "stageUsername", username: "octocat" }, tabSender);
const capSame = await call({ type: "stageCapture", password: "s3cr3t-pw" }, tabSender);
ok("已存的完全相同密码不重复提示", capSame.prompt === false && capSame.reason === "already-saved", capSame);

await call({ type: "stageUsername", username: "octocat" }, tabSender);
const capChanged = await call({ type: "stageCapture", password: "brand-new-github-pw" }, tabSender);
ok("分步登录第 2 页只提交密码也能拼回第 1 页账号并识别为 update", capChanged.prompt === true && capChanged.capture.action === "update" && capChanged.capture.existingId === baseCipher.id, capChanged);

const landedCheck = await call({ type: "checkPendingCapture" }, { tab: { id: 42 }, url: "https://github.com/dashboard" });
ok("跳转到新页面后仍能取回待更新密码提示", landedCheck.capture?.password === "brand-new-github-pw", landedCheck);

const savedUpdate = await call({
  type: "save",
  existingId: landedCheck.capture.existingId,
  name: landedCheck.capture.name,
  username: landedCheck.capture.username,
  password: landedCheck.capture.password,
  url: "https://github.com/login",
}, { tab: { id: 42 }, url: "https://github.com/dashboard" });
ok("确认更新后成功覆盖原条目而非重复新建", savedUpdate.ok === true && savedUpdate.updated === true);

const ghItem = await call({ type: "getItem", id: baseCipher.id });
ok("更新后原条目密码已变且历史密码计数为 1", ghItem.item.password === "brand-new-github-pw" && ghItem.item.passwordHistoryCount === 1, ghItem.item);

console.log("[6] 手动提交桌面应用密码 + 桌面应用分类筛选 + 删除");
const manualApp = await call({
  type: "save",
  name: "微信电脑版",
  username: "wx_orando",
  password: "wx-secret-888",
  uris: [{ uri: "app://WeChat.exe", match: null }],
  notes: "开机提示",
});
ok("手动提交桌面应用密码成功", manualApp.ok === true && Boolean(manualApp.id));

const appList = await call({ type: "list", scope: "apps" });
ok("桌面应用分类筛出 1 条", appList.items.length === 1 && appList.items[0].isApp === true, appList.items);

await call({ type: "deleteCipher", id: manualApp.id });
const afterDel = await call({ type: "list", scope: "all" });
ok("删除后回到 1 条", afterDel.total === 1);

console.log("[7] 模拟桌面端改库 -> WebSocket 推送帧触发插件自动同步");
ciphersDb.set("desktop-pushed-1", {
  id: "desktop-pushed-1",
  type: 1,
  favorite: true,
  folderId: null,
  organizationId: null,
  revisionDate: "2026-04-01T00:00:00Z",
  name: await encryptText(userKey, "桌面端刚存的密码"),
  notes: null,
  login: {
    username: await encryptText(userKey, "desk_user"),
    password: await encryptText(userKey, "desk_pw"),
    totp: null,
    uris: [{ match: null, uri: await encryptText(userKey, "https://desk.example.com") }],
  },
});
// 模拟服务端下发含 ReceiveMessage 的二进制 MsgPack 帧
wsInstances[0].emit("message", { data: new TextEncoder().encode("\x18\x94\x01\x80\xaefReceiveMessage\x91") });
await new Promise((r) => setTimeout(r, 750));
const afterWs = await call({ type: "list", scope: "all" });
ok("收到推送后后台自动完成增量同步", afterWs.total === 2 && afterWs.items.some((i) => i.name === "桌面端刚存的密码"), afterWs.items);

console.log("[8] 锁定后一切归零并断开 WebSocket");
await call({ type: "lock" });
const st2 = await call({ type: "status" });
ok("回到锁定且 WS 已关闭", st2.locked === true && wsInstances[0].readyState === 3);

console.log("");
console.log(pass + " 通过, " + fail + " 失败");
process.exit(fail === 0 ? 0 : 1);
