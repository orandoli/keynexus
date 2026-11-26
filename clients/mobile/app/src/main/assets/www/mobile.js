/**
 * PWDSV Android 手机客户端核心逻辑 v2.1：
 * - 对接 Kotlin 原生桥 `window.PwdsvAndroid`（Keystore 安全存储、指纹解锁、无跨域 HTTPS 代理、已安装应用列表、AutofillService 同步）
 * - 同时内置标准 Web 回退，方便在桌面浏览器移动模式下直接联调预览
 * - 触控交互优化：顶部四态 Bento 统计卡、列表单手一键复制、品牌圆角字母头像、彩色语义密码、动态码 SVG 进度环、三步拍照/文档 AI 导密
 */

import { PwdsvApi, ApiError, parseTwoFactorProviders, normalizeServerUrl } from "./lib/api.js";
import { deriveMasterKey, hashMasterPassword, SymmetricCryptoKey } from "./lib/crypto.js";
import { unlockUserKey, decryptSync, buildLoginCipherPayload } from "./lib/vault.js";
import { generateTotp, parseTotp } from "./lib/totp.js";
import { resolveItemScope, isScopeApplicable, SCOPE_LABELS } from "./lib/matcher.js";
import { generatePassword, estimateStrength } from "./lib/generator.js";
import { RealtimeHub } from "./lib/realtime.js";
import { PRESET_PROVIDERS, parsePasswordFile, testProviderConnection, fetchProviderModels } from "./lib/importer/index.js";
import { checkClientUpdate } from "./lib/updater.js";

const native = window.PwdsvAndroid || null;
let cbSeq = 1;
const pendingNativeCallbacks = new Map();
window.__pwdsvNativeCallback = (id, payload) => {
  const key = String(id);
  const resolve = pendingNativeCallbacks.get(key);
  if (resolve) {
    pendingNativeCallbacks.delete(key);
    resolve(payload);
  }
};

function callNativeAsync(fnLauncher) {
  const id = String(cbSeq++);
  return new Promise((resolve) => {
    pendingNativeCallbacks.set(id, resolve);
    fnLauncher(id);
  });
}

function secureSet(key, val) {
  if (native) native.saveSecureItem(key, val);
  else localStorage.setItem("pwdsv_mob_sec_" + key, val);
}
function secureGet(key) {
  if (native) return native.loadSecureItem(key);
  return localStorage.getItem("pwdsv_mob_sec_" + key);
}

function makeMobileFetch(insecureTls = false) {
  if (!native) return (...args) => fetch(...args);
  return async (url, init = {}) => {
    const res = await callNativeAsync((cbId) => {
      native.httpRequestAsync(
        cbId,
        JSON.stringify({
          url: String(url),
          method: init.method || "GET",
          headers: init.headers || {},
          body: init.body !== undefined ? String(init.body) : null,
          insecureTls: Boolean(insecureTls),
        }),
      );
    });
    if (!res?.ok) throw new Error(res?.error || "手机网络请求失败");
    return {
      ok: res.status >= 200 && res.status < 300,
      status: res.status,
      async text() {
        return res.body || "";
      },
    };
  };
}

const $ = (id) => document.getElementById(id);

const state = {
  deviceId:
    secureGet("device_id") ||
    (() => {
      const id = crypto.randomUUID();
      secureSet("device_id", id);
      return id;
    })(),
  session: null,
  items: [],
  folders: [],
  scopeFilter: "fit", // fit | universal | mobile | desktop | web | fav | all
  selectedId: null,
  editingId: null,
  revealed: false,
  totpTimer: null,
  authListTimer: null,
  authCardRefs: [],
  detailReturnTab: "vault",
  providers: [],
  activeProviderId: "",
  previewItems: [],
  pendingUpdate: null,
};

const realtimeHub = new RealtimeHub({
  onSyncNeeded: () => syncVault(true),
  onForceLogout: () => lockVault("收到服务端登出通知"),
});

/* ----------------------------------------------------- 视觉头像与密码语义工具 */

const AVATAR_GRADIENTS = [
  "linear-gradient(135deg, #2563eb, #1d4ed8)",
  "linear-gradient(135deg, #0d9488, #0f766e)",
  "linear-gradient(135deg, #7c3aed, #5b21b6)",
  "linear-gradient(135deg, #ea580c, #c2410c)",
  "linear-gradient(135deg, #0284c7, #0369a1)",
  "linear-gradient(135deg, #db2777, #9d174d)",
  "linear-gradient(135deg, #4f46e5, #3730a3)",
  "linear-gradient(135deg, #059669, #047857)",
];

function avatarGradientFor(seed) {
  const str = String(seed || "pwdsv");
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return AVATAR_GRADIENTS[Math.abs(h) % AVATAR_GRADIENTS.length];
}

function extractMonogram(rawName) {
  const clean = String(rawName || "")
    .replace(/^(https?:\/\/|app:\/\/|androidapp:\/\/)/i, "")
    .replace(/[^\p{L}\p{N}\s._-]+/gu, "")
    .trim();
  if (!clean) return "PW";
  const firstChar = Array.from(clean)[0];
  if (/[\u4e00-\u9fff]/.test(firstChar)) return firstChar;
  const parts = clean.split(/[\s._-]+/).filter(Boolean);
  if (parts.length >= 2 && /^[A-Za-z0-9]/.test(parts[0]) && /^[A-Za-z0-9]/.test(parts[1])) {
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
  const token = parts[0] || clean;
  const camel = token.match(/^[a-zA-Z][a-z0-9]*([A-Z])/);
  if (camel) return (token[0] + camel[1]).toUpperCase();
  return token.slice(0, 2).toUpperCase();
}

function applyAvatar(el, name, seed) {
  if (!el) return;
  el.textContent = extractMonogram(name);
  el.style.background = avatarGradientFor(name || seed);
}

function formatTotpSpaced(code) {
  const s = String(code || "").trim();
  if (s.length === 6) return `${s.slice(0, 3)} ${s.slice(3)}`;
  if (s.length === 8) return `${s.slice(0, 4)} ${s.slice(4)}`;
  return s;
}

function renderColoredPwd(container, pwd, revealed) {
  container.textContent = "";
  if (!revealed) {
    container.className = "m-kv-val pwd-masked";
    container.textContent = "••••••••••••";
    return;
  }
  container.className = "m-kv-val";
  if (!pwd) {
    container.textContent = "—";
    return;
  }
  for (const ch of Array.from(pwd)) {
    if (/[0-9]/.test(ch)) {
      const sp = document.createElement("span");
      sp.className = "pwd-char-num";
      sp.textContent = ch;
      container.appendChild(sp);
    } else if (/[^A-Za-z0-9]/.test(ch)) {
      const sp = document.createElement("span");
      sp.className = "pwd-char-sym";
      sp.textContent = ch;
      container.appendChild(sp);
    } else {
      container.appendChild(document.createTextNode(ch));
    }
  }
}

function renderStrength(el, pwd) {
  if (!el) return;
  if (!pwd) {
    el.hidden = true;
    return;
  }
  const { score, label, entropy } = estimateStrength(pwd);
  const cls = score <= 1 ? "strength-weak" : score === 2 ? "strength-mid" : "strength-strong";
  el.hidden = false;
  el.className = `m-strength-pill ${cls}`;
  el.textContent = `${label} · ${entropy}b`;
}

function setMobileAiStep(step) {
  document.querySelectorAll("#tab-ai .m-stepper .ms-step").forEach((el, idx) => {
    el.classList.toggle("active", idx + 1 === step);
  });
}

let toastT = null;
function toast(msg) {
  const el = $("m-toast");
  el.textContent = msg;
  el.hidden = false;
  if (toastT) clearTimeout(toastT);
  toastT = setTimeout(() => {
    el.hidden = true;
  }, 3000);
}

function makeApi(serverUrl, insecureTls) {
  return new PwdsvApi(normalizeServerUrl(serverUrl), {
    deviceId: state.deviceId,
    deviceName: "KeyNexus Android",
    deviceType: 0, // 0 = Android
    clientName: "mobile",
    fetchImpl: makeMobileFetch(insecureTls),
  });
}

async function ensureToken() {
  const s = state.session;
  if (!s) throw new Error("未解锁");
  if (s.accessToken && Date.now() < (s.tokenExpiresAt || 0)) return s.accessToken;
  const api = makeApi(s.serverUrl, s.insecureTls);
  const t = await api.refresh(s.refreshToken);
  s.accessToken = t.accessToken;
  s.refreshToken = t.refreshToken;
  s.tokenExpiresAt = Date.now() + (t.expiresIn || 3600) * 1000 - 60000;
  return s.accessToken;
}

function syncAutofillMemory() {
  if (!native) return;
  if (!state.session) {
    native.syncAutofillCache(false, "[]");
    return;
  }
  const slim = state.items
    .filter((it) => isScopeApplicable(resolveItemScope(it), "mobile"))
    .map((it) => ({
      id: it.id,
      name: it.name,
      username: it.username,
      password: it.password,
      uris: (it.uris || []).map((u) => u.uri),
      pwdsvScope: resolveItemScope(it),
    }));
  native.syncAutofillCache(true, JSON.stringify(slim));
}

/* --------------------------------------------------- 快捷解锁（指纹 / PIN） */

function getQuickUnlockRecord() {
  try {
    const raw = secureGet("quick_unlock_v2");
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function saveQuickUnlockRecord(pin, sessionObj) {
  secureSet(
    "quick_unlock_v2",
    JSON.stringify({
      pin,
      email: sessionObj.email,
      serverUrl: sessionObj.serverUrl,
      insecureTls: sessionObj.insecureTls,
      userId: sessionObj.userId,
      keyId: sessionObj.keyId,
      userKeyB64: sessionObj.userKey.toB64(),
      refreshToken: sessionObj.refreshToken,
    }),
  );
}

function showAuthView(preferQuick = true) {
  $("m-auth").hidden = false;
  $("m-app").hidden = true;

  const quick = getQuickUnlockRecord();
  const lastMeta = JSON.parse(secureGet("last_account") || "{}");
  $("m-server").value = lastMeta.serverUrl || "";
  $("m-email").value = lastMeta.email || "";
  $("m-insecure").checked = Boolean(lastMeta.insecureTls);

  const useQuick = preferQuick && Boolean(quick);
  $("m-quick-form").hidden = !useQuick;
  $("m-master-form").hidden = useQuick;

  if (useQuick) {
    $("m-quick-account").textContent = `${quick.email} · ${quick.serverUrl}`;
    $("btn-m-bio").hidden = !(native && native.canUseBiometric());
  }
}

$("btn-m-use-master").addEventListener("click", () => showAuthView(false));

async function restoreFromQuickRecord(quick) {
  const api = makeApi(quick.serverUrl, quick.insecureTls);
  const refreshed = await api.refresh(quick.refreshToken);
  const userKey = SymmetricCryptoKey.fromB64(quick.userKeyB64);
  const syncData = await api.sync(refreshed.accessToken);
  const vault = await decryptSync(syncData, userKey);

  state.session = {
    userKey,
    userId: syncData.profile?.id || quick.userId,
    keyId: syncData.userDecryption?.userKeyId || quick.keyId || null,
    email: quick.email,
    serverUrl: quick.serverUrl,
    insecureTls: Boolean(quick.insecureTls),
    accessToken: refreshed.accessToken,
    refreshToken: refreshed.refreshToken,
    tokenExpiresAt: Date.now() + (refreshed.expiresIn || 3600) * 1000 - 60000,
  };
  state.items = vault.items;
  state.folders = vault.folders;
  saveQuickUnlockRecord(quick.pin, state.session);
  await enterMobileApp();
}

$("btn-m-bio").addEventListener("click", async () => {
  const quick = getQuickUnlockRecord();
  if (!quick || !native) return;
  const res = await callNativeAsync((cbId) => native.promptBiometric(cbId));
  if (res?.ok) {
    try {
      await restoreFromQuickRecord(quick);
      toast("生物识别解锁成功");
    } catch (e) {
      $("m-quick-err").hidden = false;
      $("m-quick-err").textContent = String(e.message || e);
    }
  }
});

$("m-quick-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const quick = getQuickUnlockRecord();
  const errEl = $("m-quick-err");
  errEl.hidden = true;
  if (!quick) return;

  if ($("m-pin-in").value.trim() !== quick.pin) {
    errEl.hidden = false;
    errEl.textContent = "PIN 不正确";
    return;
  }
  try {
    await restoreFromQuickRecord(quick);
    $("m-pin-in").value = "";
  } catch (err) {
    errEl.hidden = false;
    errEl.textContent = String(err.message || err);
  }
});

$("m-master-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("btn-m-login");
  const errEl = $("m-master-err");
  errEl.hidden = true;
  btn.disabled = true;

  try {
    const serverUrl = normalizeServerUrl($("m-server").value);
    const email = $("m-email").value.trim();
    const password = $("m-password").value;
    const insecureTls = $("m-insecure").checked;
    const setupPin = $("m-setup-pin").value.trim();

    const api = makeApi(serverUrl, insecureTls);
    const kdf = await api.prelogin(email);
    const masterKey = await deriveMasterKey(password, email, kdf);
    const masterPasswordHash = await hashMasterPassword(masterKey, password);

    const has2fa = !$("m-2fa-box").hidden;
    let tokens;
    try {
      tokens = await api.login({
        email,
        masterPasswordHash,
        twoFactorToken: has2fa ? $("m-2fa-code").value.trim() || undefined : undefined,
        twoFactorProvider: has2fa ? Number($("m-2fa-provider").value || 0) : 0,
      });
    } catch (loginErr) {
      if (loginErr instanceof ApiError && loginErr.status === 400) {
        const providers = parseTwoFactorProviders(loginErr);
        if (providers.length) {
          const sel = $("m-2fa-provider");
          sel.textContent = "";
          for (const p of providers) {
            const opt = document.createElement("option");
            opt.value = String(p.id);
            opt.textContent = p.name;
            sel.appendChild(opt);
          }
          $("m-2fa-box").hidden = false;
          return;
        }
      }
      throw loginErr;
    }

    const syncData = await api.sync(tokens.accessToken);
    const { userKey } = await unlockUserKey(syncData.profile, masterKey);
    const vault = await decryptSync(syncData, userKey);

    state.session = {
      userKey,
      userId: syncData.profile?.id || "",
      keyId: syncData.userDecryption?.userKeyId || null,
      email,
      serverUrl,
      insecureTls,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      tokenExpiresAt: Date.now() + (tokens.expiresIn || 3600) * 1000 - 60000,
    };
    state.items = vault.items;
    state.folders = vault.folders;

    secureSet("last_account", JSON.stringify({ serverUrl, email, insecureTls }));
    if (setupPin.length >= 4) {
      saveQuickUnlockRecord(setupPin, state.session);
    }

    $("m-password").value = "";
    $("m-setup-pin").value = "";
    $("m-2fa-box").hidden = true;
    await enterMobileApp();
  } catch (err) {
    errEl.hidden = false;
    errEl.textContent = String(err.message || err);
  } finally {
    btn.disabled = false;
  }
});

/* ---------------------------------------------------------- 主界面与四态列表 */

async function enterMobileApp() {
  $("m-auth").hidden = true;
  $("m-app").hidden = false;
  if ($("m-top-sub")) {
    $("m-top-sub").textContent = `${state.session.email} · 共 ${state.items.length} 条`;
  }
  syncAutofillMemory();
  realtimeHub.connect(state.session.serverUrl, state.session.accessToken);
  switchTab("vault");
  renderVaultList();
  await checkNativePendingSaves();
  checkMobileUpdate(true).catch(() => {});
}

function stopAuthListTimer() {
  if (state.authListTimer) clearInterval(state.authListTimer);
  state.authListTimer = null;
}

function lockVault(msg = "已锁定密码库") {
  if (state.totpTimer) clearInterval(state.totpTimer);
  state.totpTimer = null;
  stopAuthListTimer();
  realtimeHub.disconnect();
  state.session = null;
  state.items = [];
  syncAutofillMemory();
  showAuthView(true);
  toast(msg);
}

async function syncVault(silent = false) {
  if (!state.session) return;
  try {
    const token = await ensureToken();
    const api = makeApi(state.session.serverUrl, state.session.insecureTls);
    const data = await api.sync(token);
    const vault = await decryptSync(data, state.session.userKey);
    state.items = vault.items;
    state.folders = vault.folders;
    if ($("m-top-sub")) {
      $("m-top-sub").textContent = `${state.session.email} · 共 ${state.items.length} 条`;
    }
    syncAutofillMemory();
    renderVaultList();
    if (!$("tab-auth").hidden) renderAuthList();
    if (!silent) toast(`已同步 ${state.items.length} 条记录`);
  } catch (e) {
    if (!silent) toast("同步失败：" + e.message);
  }
}

function switchTab(tabName) {
  if (tabName !== "detail" && state.totpTimer) {
    clearInterval(state.totpTimer);
    state.totpTimer = null;
  }
  if (tabName !== "auth") {
    stopAuthListTimer();
  }

  const titles = {
    vault: "密码库",
    auth: "Authenticator",
    detail: "凭据详情",
    ai: "拍照与多格式 AI 导密",
    edit: state.editingId ? "编辑密码" : "提交新密码",
    settings: "系统填充与模型源",
  };
  $("m-top-title").textContent = titles[tabName] || "PWDSV";

  for (const t of ["vault", "auth", "detail", "ai", "edit", "settings"]) {
    $("tab-" + t).hidden = t !== tabName;
  }
  document.querySelectorAll(".m-tab").forEach((b) => {
    const returnTab = state.detailReturnTab === "auth" ? "auth" : "vault";
    const active = b.dataset.tab === tabName || (tabName === "detail" && b.dataset.tab === returnTab);
    b.classList.toggle("active", active);
  });

  if (tabName === "auth") {
    renderAuthList();
    state.authListTimer = setInterval(refreshAuthCodesOnly, 1000);
  }
  if (tabName === "ai") {
    refreshAiProviderDropdown();
    setMobileAiStep(state.previewItems.length > 0 ? 3 : 1);
  }
  if (tabName === "settings") populateProviderSettingsUI();
}

document.querySelectorAll(".m-tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    if (btn.dataset.tab === "edit") {
      state.detailReturnTab = "vault";
      prepareEditor(null);
    }
    switchTab(btn.dataset.tab);
  });
});

$("btn-m-sync").addEventListener("click", () => syncVault(false));
$("btn-m-lock").addEventListener("click", () => lockVault());
$("btn-m-empty-add")?.addEventListener("click", () => {
  prepareEditor(null);
  switchTab("edit");
});
$("btn-m-empty-ai")?.addEventListener("click", () => switchTab("ai"));
$("btn-m-jump-prov")?.addEventListener("click", () => switchTab("settings"));

// 处理 Android AutofillService 从其他手机 App 捕获到的新密码
async function checkNativePendingSaves() {
  if (!native || !state.session) return;
  try {
    const arr = JSON.parse(native.drainPendingAutofillSaves() || "[]");
    if (!arr.length) return;
    const first = arr[0];
    prepareEditor(null, first);
    switchTab("edit");
    toast("已捕获刚才在手机应用中登录的新账号，请确认保存");
  } catch {
    /* 忽略 */
  }
}
window.__onPwdsvResume = checkNativePendingSaves;

const SHORT_SCOPE_LABELS = {
  universal: "通用",
  mobile: "手机",
  desktop: "电脑",
  web: "网页",
};

function updateBentoCounters() {
  const counts = { universal: 0, mobile: 0, desktop: 0, web: 0 };
  for (const it of state.items) {
    const sc = resolveItemScope(it);
    counts[sc] = (counts[sc] || 0) + 1;
  }
  if ($("mc-uni")) $("mc-uni").textContent = String(counts.universal);
  if ($("mc-mob")) $("mc-mob").textContent = String(counts.mobile);
  if ($("mc-desk")) $("mc-desk").textContent = String(counts.desktop);
  if ($("mc-web")) $("mc-web").textContent = String(counts.web);

  document.querySelectorAll(".m-bento-item[data-bento]").forEach((b) => {
    b.classList.toggle("active", b.dataset.bento === state.scopeFilter);
  });
  document.querySelectorAll("#m-scope-chips .chip").forEach((c) => {
    c.classList.toggle("active", c.dataset.scope === state.scopeFilter);
  });
}

function renderVaultList() {
  updateBentoCounters();
  const q = $("m-search").value.trim().toLowerCase();
  let list = [...state.items];

  if (state.scopeFilter === "fit") {
    list = list.filter((it) => isScopeApplicable(resolveItemScope(it), "mobile"));
  } else if (state.scopeFilter === "fav") {
    list = list.filter((it) => it.favorite);
  } else if (["universal", "mobile", "desktop", "web"].includes(state.scopeFilter)) {
    list = list.filter((it) => resolveItemScope(it) === state.scopeFilter);
  }

  if (q) {
    list = list.filter((it) =>
      [it.name, it.username, it.notes, ...(it.uris || []).map((u) => u.uri)]
        .join(" ")
        .toLowerCase()
        .includes(q),
    );
  }

  list.sort((a, b) => {
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
    return String(a.name || "").localeCompare(String(b.name || ""), "zh-CN");
  });

  const ul = $("m-list");
  ul.textContent = "";
  $("m-empty").hidden = list.length > 0;

  for (const item of list) {
    const li = document.createElement("li");
    li.addEventListener("click", () => openDetail(item.id));

    const avatar = document.createElement("div");
    avatar.className = "m-avatar";
    applyAvatar(avatar, item.name || item.username, item.id);

    const body = document.createElement("div");
    body.className = "m-row-body";

    const t1 = document.createElement("div");
    t1.className = "t1";
    const nm = document.createElement("span");
    nm.className = "m-title-ellipsis";
    nm.textContent = (item.favorite ? "★ " : "") + (item.name || "(未命名)");

    const sc = resolveItemScope(item);
    const tag = document.createElement("em");
    tag.className = `m-tag ${sc}`;
    tag.textContent = SHORT_SCOPE_LABELS[sc] || "通用";
    t1.append(nm, tag);

    const t2 = document.createElement("div");
    t2.className = "t2";
    t2.textContent = item.username || item.uris?.[0]?.uri || "无用户名";

    body.append(t1, t2);
    li.append(avatar, body);

    if (item.password) {
      const btnCopy = document.createElement("button");
      btnCopy.type = "button";
      btnCopy.className = "m-quick-copy";
      btnCopy.textContent = "复制";
      btnCopy.addEventListener("click", (ev) => {
        ev.stopPropagation();
        copyTextSensitive(item.password, `「${item.name}」密码`);
      });
      li.appendChild(btnCopy);
    }

    ul.appendChild(li);
  }
}

$("m-search").addEventListener("input", renderVaultList);
document.querySelectorAll("#m-scope-chips .chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    state.scopeFilter = chip.dataset.scope;
    renderVaultList();
  });
});
document.querySelectorAll(".m-bento-item[data-bento]").forEach((tile) => {
  tile.addEventListener("click", () => {
    const target = tile.dataset.bento;
    state.scopeFilter = state.scopeFilter === target ? "fit" : target;
    renderVaultList();
  });
});

/* --------------------------------------------------------------- 详情与复制 */

function copyTextSensitive(val, label) {
  if (!val) return;
  if (native) native.copySecret(val, 30);
  else navigator.clipboard?.writeText?.(val);
  toast(`${label}已安全复制（30 秒后自动清空）`);
}

function uriIcon(uri) {
  const u = String(uri || "");
  if (/^androidapp:\/\//i.test(u)) return "📱";
  if (/^app:\/\//i.test(u)) return "💻";
  return "🌐";
}

function openDetail(id, returnTab = state.detailReturnTab || "vault") {
  if (state.totpTimer) clearInterval(state.totpTimer);
  const item = state.items.find((i) => i.id === id);
  if (!item) return;
  state.detailReturnTab = returnTab === "auth" ? "auth" : "vault";
  state.selectedId = id;
  state.revealed = false;
  $("btn-md-eye").textContent = "显示";

  applyAvatar($("md-avatar"), item.name || item.username, item.id);
  $("md-name").textContent = item.name || "(未命名)";
  if ($("btn-md-fav")) {
    $("btn-md-fav").textContent = item.favorite ? "★" : "☆";
    $("btn-md-fav").style.opacity = item.favorite ? "1" : "0.45";
  }

  const sc = resolveItemScope(item);
  const badges = $("md-badges");
  badges.textContent = "";
  const scTag = document.createElement("span");
  scTag.className = `m-tag ${sc}`;
  scTag.textContent = SCOPE_LABELS[sc] || "三端通用";
  badges.appendChild(scTag);
  if (item.pwdsvOriginDevice) {
    const oTag = document.createElement("span");
    oTag.className = "m-tag";
    oTag.textContent = `来源：${item.pwdsvOriginDevice}`;
    badges.appendChild(oTag);
  }

  $("md-user").textContent = item.username || "—";
  renderStrength($("md-strength"), item.password);
  renderColoredPwd($("md-pwd"), item.password, false);

  $("md-uris-row").hidden = !item.uris?.length;
  $("md-uris").textContent = "";
  for (const u of item.uris || []) {
    const chip = document.createElement("div");
    chip.className = "m-uri-chip";
    const ic = document.createElement("span");
    ic.textContent = uriIcon(u.uri);
    const sp = document.createElement("span");
    sp.textContent = u.uri;
    chip.append(ic, sp);
    $("md-uris").appendChild(chip);
  }

  $("md-notes-row").hidden = !item.notes;
  $("md-notes").textContent = item.notes || "";

  $("md-totp-row").hidden = !item.totp;
  if (item.totp) {
    const circumference = 56.55;
    const tick = async () => {
      try {
        const { code, remaining, period } = await generateTotp(item.totp);
        $("md-totp").textContent = formatTotpSpaced(code);
        $("md-totp-left").textContent = `${remaining}s`;
        const c = $("md-totp-circle");
        if (c) {
          const offset = circumference * (1 - remaining / (period || 30));
          c.setAttribute("stroke-dashoffset", offset.toFixed(2));
          c.style.stroke = remaining <= 5 ? "#f59e0b" : "#34d399";
        }
      } catch {
        $("md-totp").textContent = "无效密钥";
        $("md-totp-left").textContent = "";
      }
    };
    tick();
    state.totpTimer = setInterval(tick, 1000);
  }

  switchTab("detail");
}

$("btn-md-fav")?.addEventListener("click", async () => {
  const item = state.items.find((i) => i.id === state.selectedId);
  if (!item || !state.session) return;
  try {
    const nextFav = !item.favorite;
    const payload = await buildLoginCipherPayload(
      {
        name: item.name,
        username: item.username,
        password: item.password,
        uris: item.uris || [],
        totp: item.totp || "",
        folderId: item.folderId || null,
        favorite: nextFav,
        notes: item.notes || "",
        fields: item.fields || [],
        pwdsvScope: resolveItemScope(item),
        pwdsvOriginDevice: item.pwdsvOriginDevice || "mobile",
      },
      {
        userKey: state.session.userKey,
        userId: state.session.userId,
        keyId: state.session.keyId,
        existingItem: item,
      },
    );
    const token = await ensureToken();
    const api = makeApi(state.session.serverUrl, state.session.insecureTls);
    await api.updateCipher(token, item.id, payload);
    await syncVault(true);
    openDetail(item.id);
    toast(nextFav ? "★ 已收藏" : "已取消收藏");
  } catch (err) {
    toast("操作失败：" + err.message);
  }
});

$("btn-md-back").addEventListener("click", () => switchTab(state.detailReturnTab || "vault"));
$("btn-md-eye").addEventListener("click", () => {
  const item = state.items.find((i) => i.id === state.selectedId);
  if (!item) return;
  state.revealed = !state.revealed;
  renderColoredPwd($("md-pwd"), item.password, state.revealed);
  $("btn-md-eye").textContent = state.revealed ? "隐藏" : "显示";
});

document.querySelectorAll("[data-mcopy]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const item = state.items.find((i) => i.id === state.selectedId);
    if (!item) return;
    const f = btn.dataset.mcopy;
    if (f === "username") copyTextSensitive(item.username, "账号");
    else if (f === "password") copyTextSensitive(item.password, "密码");
    else if (f === "totp" && item.totp) {
      const { code } = await generateTotp(item.totp);
      copyTextSensitive(code, "验证码");
    }
  });
});

$("btn-md-edit").addEventListener("click", () => {
  const item = state.items.find((i) => i.id === state.selectedId);
  if (item) {
    prepareEditor(item);
    switchTab("edit");
  }
});

$("btn-md-del").addEventListener("click", async () => {
  const item = state.items.find((i) => i.id === state.selectedId);
  if (!item || !confirm(`确认删除「${item.name}」？`)) return;
  const token = await ensureToken();
  const api = makeApi(state.session.serverUrl, state.session.insecureTls);
  await api.deleteCipher(token, item.id);
  await syncVault(true);
  switchTab(state.detailReturnTab || "vault");
  toast("已删除");
});

/* ----------------------------------------------------- Authenticator 独立竖栏 */

async function refreshAuthCodesOnly() {
  const circumference = 144.51;
  await Promise.all(
    state.authCardRefs.map(async (ref) => {
      try {
        const { code, remaining, period } = await generateTotp(ref.totp);
        ref.currentCode = code;
        ref.codeEl.classList.remove("invalid");
        ref.codeEl.textContent = formatTotpSpaced(code);
        ref.leftEl.textContent = `${remaining}`;
        ref.leftEl.classList.toggle("urgent", remaining <= 5);
        const total = period || 30;
        const offset = circumference * (1 - remaining / total);
        ref.circleEl.setAttribute("stroke-dashoffset", offset.toFixed(2));
        ref.circleEl.style.stroke = remaining <= 5 ? "#f59e0b" : "#34d399";
      } catch {
        ref.currentCode = "";
        ref.codeEl.classList.add("invalid");
        ref.codeEl.textContent = "密钥格式无效";
        ref.leftEl.textContent = "";
      }
    }),
  );
}

function renderAuthList() {
  const q = ($("ma-search")?.value || "").trim().toLowerCase();
  let list = state.items.filter((it) => Boolean(it.totp && String(it.totp).trim()));

  if (q) {
    list = list.filter((it) =>
      [it.name, it.username, it.notes, ...(it.uris || []).map((u) => u.uri)]
        .join(" ")
        .toLowerCase()
        .includes(q),
    );
  }

  list.sort((a, b) => {
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
    return String(a.name || "").localeCompare(String(b.name || ""), "zh-CN");
  });

  const ul = $("ma-list");
  if (!ul) return;
  ul.textContent = "";
  state.authCardRefs = [];
  if ($("ma-empty")) $("ma-empty").hidden = list.length > 0;

  for (const item of list) {
    const li = document.createElement("li");
    li.className = "m-auth-card";

    const accent = document.createElement("span");
    accent.className = "m-auth-accent";
    accent.style.background = avatarGradientFor(item.name || item.id);

    const ringAvatar = document.createElement("div");
    ringAvatar.className = "m-auth-ring-avatar";
    ringAvatar.innerHTML = `
      <svg class="m-auth-ring-svg" viewBox="0 0 52 52" width="52" height="52">
        <circle class="r-bg" cx="26" cy="26" r="23" />
        <circle class="r-fg" cx="26" cy="26" r="23" stroke-dasharray="144.51" stroke-dashoffset="0" />
      </svg>
    `;
    const avatar = document.createElement("div");
    avatar.className = "m-avatar round";
    applyAvatar(avatar, item.name || item.username, item.id);
    const leftEl = document.createElement("em");
    leftEl.className = "m-auth-sec-badge";
    leftEl.textContent = "--";
    ringAvatar.append(avatar, leftEl);

    const circleEl = ringAvatar.querySelector(".r-fg");

    const center = document.createElement("div");
    center.className = "m-auth-card-center";

    const titleLine = document.createElement("div");
    titleLine.className = "m-auth-title-line";
    const nm = document.createElement("span");
    nm.className = "m-auth-card-name";
    nm.textContent = (item.favorite ? "★ " : "") + (item.name || "(未命名)");
    const usr = document.createElement("span");
    usr.className = "m-auth-card-user";
    usr.textContent = item.username || item.uris?.[0]?.uri || "验证器";
    titleLine.append(nm, usr);

    const codeEl = document.createElement("code");
    codeEl.className = "m-auth-code";
    codeEl.textContent = "••• •••";

    center.append(titleLine, codeEl);

    const btnDetail = document.createElement("button");
    btnDetail.type = "button";
    btnDetail.className = "m-auth-chevron";
    btnDetail.setAttribute("aria-label", "查看详情");
    btnDetail.innerHTML = `
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M9 6l6 6-6 6" />
      </svg>
    `;
    btnDetail.addEventListener("click", (ev) => {
      ev.stopPropagation();
      openDetail(item.id, "auth");
    });

    const ref = {
      id: item.id,
      name: item.name || "Authenticator",
      totp: item.totp,
      currentCode: "",
      codeEl,
      circleEl,
      leftEl,
    };

    li.addEventListener("click", async () => {
      let code = ref.currentCode;
      if (!code) {
        try {
          code = (await generateTotp(item.totp)).code;
        } catch {
          toast("Authenticator 密钥格式无效");
          return;
        }
      }
      li.classList.add("copied");
      setTimeout(() => li.classList.remove("copied"), 450);
      copyTextSensitive(code, `「${ref.name}」验证码 ${code}`);
    });

    li.append(accent, ringAvatar, center, btnDetail);
    ul.appendChild(li);
    state.authCardRefs.push(ref);
  }

  refreshAuthCodesOnly();
}

function toggleMobileAuthAddCard(show) {
  const card = $("ma-add-card");
  if (!card) return;
  const open = show !== undefined ? Boolean(show) : card.hidden;
  card.hidden = !open;
  if ($("ma-add-err")) $("ma-add-err").hidden = true;
  if (open) {
    document.querySelector(".m-main")?.scrollTo({ top: 0, behavior: "smooth" });
    $("ma-secret")?.focus();
  }
}

$("ma-search")?.addEventListener("input", renderAuthList);
$("btn-ma-toggle-add")?.addEventListener("click", () => toggleMobileAuthAddCard());
$("btn-ma-fab")?.addEventListener("click", () => toggleMobileAuthAddCard(true));
$("btn-ma-cancel-add")?.addEventListener("click", () => toggleMobileAuthAddCard(false));
$("btn-ma-empty-add")?.addEventListener("click", () => toggleMobileAuthAddCard(true));

$("btn-ma-scan-qr")?.addEventListener("click", () => $("ma-qr-input")?.click());
$("ma-qr-input")?.addEventListener("change", async (e) => {
  const file = e.target.files?.[0];
  e.target.value = "";
  if (!file) return;
  const errEl = $("ma-add-err");
  if (errEl) errEl.hidden = true;
  try {
    if (typeof window.BarcodeDetector !== "function") {
      throw new Error("当前系统 WebView 暂不支持本地二维码识别，请直接粘贴 otpauth:// 或 Base32 密钥");
    }
    const bmp = await createImageBitmap(file);
    const detector = new window.BarcodeDetector({ formats: ["qr_code"] });
    const barcodes = await detector.detect(bmp);
    const hit =
      barcodes.find((b) => /^otpauth:\/\//i.test(b.rawValue || "")) ||
      barcodes.find((b) => Boolean(b.rawValue));
    if (!hit?.rawValue) {
      throw new Error("未能在图片中识别到有效二维码，请对准后重试或直接粘贴密钥");
    }
    $("ma-secret").value = hit.rawValue.trim();
    $("ma-secret").dispatchEvent(new Event("input"));
    toast("✓ 已识别二维码密钥，请确认后保存");
  } catch (err) {
    if (errEl) {
      errEl.hidden = false;
      errEl.textContent = String(err.message || err);
    }
  }
});

$("ma-secret")?.addEventListener("input", () => {
  const raw = $("ma-secret").value.trim();
  if (!/^otpauth:\/\//i.test(raw)) return;
  try {
    const parsed = parseTotp(raw);
    if (parsed.issuer && !$("ma-name").value.trim()) $("ma-name").value = parsed.issuer;
    if (parsed.account && !$("ma-user").value.trim()) $("ma-user").value = parsed.account;
  } catch {
    /* 忽略输入未完成时的解析异常 */
  }
});

$("ma-add-card")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("btn-ma-save");
  const errEl = $("ma-add-err");
  errEl.hidden = true;
  btn.disabled = true;

  try {
    const secret = $("ma-secret").value.trim();
    const name = $("ma-name").value.trim();
    const username = $("ma-user").value.trim();
    if (!secret || !name) throw new Error("请填写 Authenticator 密钥和服务名称");
    await generateTotp(secret);

    const payload = await buildLoginCipherPayload(
      {
        name,
        username,
        password: "",
        uris: [],
        totp: secret,
        favorite: false,
        notes: "",
        pwdsvScope: "universal",
        pwdsvOriginDevice: "mobile",
      },
      {
        userKey: state.session.userKey,
        userId: state.session.userId,
        keyId: state.session.keyId,
      },
    );

    const token = await ensureToken();
    const api = makeApi(state.session.serverUrl, state.session.insecureTls);
    await api.createCipher(token, payload);

    $("ma-add-card").reset();
    toggleMobileAuthAddCard(false);
    await syncVault(true);
    renderAuthList();
    toast("Authenticator 验证器已加密保存");
  } catch (err) {
    errEl.hidden = false;
    errEl.textContent = String(err.message || err);
  } finally {
    btn.disabled = false;
  }
});

/* ----------------------------------------------------- 手动提交密码与绑定手机应用 */

function prepareEditor(item = null, captured = null) {
  $("me-pwd").type = "password";
  $("btn-me-eye").textContent = "显示";
  if (item) {
    state.editingId = item.id;
    $("me-title").textContent = "编辑密码";
    $("me-name").value = item.name || "";
    $("me-scope").value = resolveItemScope(item);
    $("me-user").value = item.username || "";
    $("me-pwd").value = item.password || "";
    $("me-uris").value = (item.uris || []).map((u) => u.uri).join("\n");
    $("me-totp").value = item.totp || "";
    if ($("me-fav")) $("me-fav").checked = Boolean(item.favorite);
    $("me-notes").value = item.notes || "";
  } else {
    state.editingId = null;
    $("me-title").textContent = "提交新密码";
    $("me-name").value = captured?.webDomain || captured?.packageName || "";
    $("me-scope").value = captured?.packageName && !captured?.webDomain ? "mobile" : "universal";
    $("me-user").value = captured?.username || "";
    $("me-pwd").value = captured?.password || "";
    const autoUris = [];
    if (captured?.packageName) autoUris.push(`androidapp://${captured.packageName}`);
    if (captured?.webDomain) autoUris.push(`https://${captured.webDomain}`);
    $("me-uris").value = autoUris.join("\n");
    $("me-totp").value = "";
    if ($("me-fav")) $("me-fav").checked = false;
    $("me-notes").value = "";
  }
  renderStrength($("me-pwd-strength"), $("me-pwd").value);
}

$("me-pwd").addEventListener("input", () => {
  renderStrength($("me-pwd-strength"), $("me-pwd").value);
});

$("btn-me-eye").addEventListener("click", () => {
  const h = $("me-pwd").type === "password";
  $("me-pwd").type = h ? "text" : "password";
  $("btn-me-eye").textContent = h ? "隐藏" : "显示";
});

$("btn-me-gen").addEventListener("click", () => {
  $("me-pwd").value = generatePassword({ length: 18, symbols: true });
  $("me-pwd").type = "text";
  $("btn-me-eye").textContent = "隐藏";
  renderStrength($("me-pwd-strength"), $("me-pwd").value);
});

$("btn-me-load-apps").addEventListener("click", () => {
  const sel = $("me-app-picker");
  sel.textContent = "";
  if (!native) {
    const opt = document.createElement("option");
    opt.value = "com.tencent.mm";
    opt.textContent = "示例：微信 (com.tencent.mm)";
    sel.appendChild(opt);
    toast("当前为浏览器预览模式；在 Android APK 中会列出本机全部应用");
    return;
  }
  const apps = JSON.parse(native.listInstalledApps() || "[]");
  for (const a of apps) {
    const opt = document.createElement("option");
    opt.value = a.packageName;
    opt.textContent = `${a.name} (${a.packageName})`;
    sel.appendChild(opt);
  }
  toast(`已读取 ${apps.length} 个手机应用`);
});

$("btn-me-bind-app").addEventListener("click", () => {
  const pkg = $("me-app-picker").value;
  if (!pkg) return;
  const uri = `androidapp://${pkg}`;
  const cur = $("me-uris").value.trim();
  $("me-uris").value = cur ? `${cur}\n${uri}` : uri;
});

$("m-edit-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!$("me-pwd").value && !$("me-totp").value.trim()) {
    toast("密码和 Authenticator 密钥不能同时为空");
    return;
  }
  const btn = $("btn-me-save");
  btn.disabled = true;
  try {
    const existingItem = state.editingId ? state.items.find((i) => i.id === state.editingId) : null;
    const uris = $("me-uris")
      .value.split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map((uri) => ({ uri, match: null }));
    const payload = await buildLoginCipherPayload(
      {
        name: $("me-name").value.trim(),
        username: $("me-user").value.trim(),
        password: $("me-pwd").value,
        uris,
        totp: $("me-totp").value.trim(),
        favorite: Boolean($("me-fav")?.checked),
        notes: $("me-notes").value.trim(),
        pwdsvScope: $("me-scope").value || "universal",
        pwdsvOriginDevice: "mobile",
      },
      {
        userKey: state.session.userKey,
        userId: state.session.userId,
        keyId: state.session.keyId,
        existingItem,
      },
    );

    const token = await ensureToken();
    const api = makeApi(state.session.serverUrl, state.session.insecureTls);
    const saved = existingItem
      ? await api.updateCipher(token, existingItem.id, payload)
      : await api.createCipher(token, payload);

    await syncVault(true);
    openDetail(saved?.id || existingItem?.id, state.detailReturnTab || "vault");
    toast("密码已加密上传服务器");
  } catch (err) {
    toast("保存失败：" + err.message);
  } finally {
    btn.disabled = false;
  }
});

/* -------------------------------------------- 拍照 & 多格式文档 AI 识密上传 */

function loadMobileProviders() {
  try {
    const raw = JSON.parse(secureGet("ai_providers_v2") || "null");
    if (raw?.providers?.length) {
      state.providers = raw.providers;
      state.activeProviderId = raw.activeProviderId || raw.providers[0].id;
      return;
    }
  } catch {
    /* 默认 */
  }
  state.providers = [
    { ...PRESET_PROVIDERS[1], id: "m-qwen", apiKey: "", customHeaders: "" },
    { ...PRESET_PROVIDERS[2], id: "m-gemini", apiKey: "", customHeaders: "" },
    { ...PRESET_PROVIDERS[0], id: "m-deepseek", apiKey: "", customHeaders: "" },
  ];
  state.activeProviderId = state.providers[0].id;
}

function saveMobileProviders() {
  secureSet(
    "ai_providers_v2",
    JSON.stringify({
      activeProviderId: state.activeProviderId,
      providers: state.providers,
    }),
  );
}

function refreshAiProviderDropdown() {
  const sel = $("m-ai-provider");
  sel.textContent = "";
  for (const p of state.providers) {
    const opt = document.createElement("option");
    opt.value = p.id;
    const tag = p.apiKey || p.requiresKey === false ? "已就绪" : "待填 Key";
    opt.textContent = `${p.name} · ${p.visionModel || p.textModel} [${tag}]`;
    sel.appendChild(opt);
  }
  sel.value = state.activeProviderId;
}

$("m-ai-provider").addEventListener("change", () => {
  state.activeProviderId = $("m-ai-provider").value;
  saveMobileProviders();
});

async function compressPhotoIfNeeded(file) {
  if (!file.type.startsWith("image/")) {
    return { name: file.name, mimeType: file.type, bytes: new Uint8Array(await file.arrayBuffer()) };
  }
  const bmp = await createImageBitmap(file);
  const maxDim = 1500;
  const scale = Math.min(1, maxDim / Math.max(bmp.width, bmp.height));
  const canvas = document.createElement("canvas");
  canvas.width = Math.round(bmp.width * scale);
  canvas.height = Math.round(bmp.height * scale);
  canvas.getContext("2d").drawImage(bmp, 0, 0, canvas.width, canvas.height);
  const blob = await new Promise((r) => canvas.toBlob(r, "image/jpeg", 0.88));
  return { name: file.name, mimeType: "image/jpeg", bytes: new Uint8Array(await blob.arrayBuffer()) };
}

async function handleMobileFileImport(fileObj) {
  const st = $("m-ai-status");
  const errEl = $("m-ai-err");
  errEl.hidden = true;
  st.hidden = false;
  setMobileAiStep(2);

  try {
    const prov = state.providers.find((p) => p.id === state.activeProviderId) || state.providers[0];
    const res = await parsePasswordFile(fileObj, {
      provider: prov,
      existingVaultItems: state.items,
      forceAi: $("m-force-ai").checked,
      fetchImpl: makeMobileFetch(Boolean(state.session?.insecureTls)),
      onProgress: (txt) => {
        st.textContent = txt;
      },
    });
    state.previewItems = res.items || [];
    st.textContent = `✓ 从「${res.fileName}」识别出 ${state.previewItems.length} 条密码，请核对后上传`;
    setMobileAiStep(state.previewItems.length > 0 ? 3 : 1);
    renderMobilePreviewCards();
  } catch (err) {
    setMobileAiStep(1);
    st.hidden = true;
    errEl.hidden = false;
    errEl.textContent = String(err.message || err);
  }
}

$("btn-m-camera").addEventListener("click", () => $("m-camera-input").click());
$("btn-m-file").addEventListener("click", () => $("m-file-input").click());

for (const id of ["m-camera-input", "m-file-input"]) {
  $(id).addEventListener("change", async (e) => {
    const f = e.target.files?.[0];
    e.target.value = "";
    if (!f) return;
    const prepped = await compressPhotoIfNeeded(f);
    await handleMobileFileImport(prepped);
  });
}

$("btn-m-parse-text").addEventListener("click", async () => {
  const txt = $("m-raw-text").value.trim();
  if (!txt) {
    toast("请先粘贴需要解析的密码文字");
    return;
  }
  await handleMobileFileImport({
    name: "手机粘贴备忘.txt",
    mimeType: "text/plain",
    bytes: new TextEncoder().encode(txt),
  });
});

function renderMobilePreviewCards() {
  const box = $("m-preview-box");
  const container = $("m-preview-cards");
  container.textContent = "";
  box.hidden = state.previewItems.length === 0;
  if ($("m-preview-title")) {
    $("m-preview-title").textContent = `识别结果核对（${state.previewItems.length} 条）`;
  }

  state.previewItems.forEach((row) => {
    const card = document.createElement("div");
    card.className = "preview-card";
    const statusLabel = row.duplicateAction === "update" ? "更新原密" : "新建记录";
    card.innerHTML = `
      <div class="m-row-between" style="margin-bottom:8px">
        <label style="display:flex;align-items:center;gap:7px;font-weight:600;font-size:13px">
          <input type="checkbox" class="pc-chk" />
          <span class="m-tag">${statusLabel}</span>
        </label>
        <select class="pc-scope" style="width:132px;padding:5px 8px;font-size:12px">
          <option value="universal">🌐 三端通用</option>
          <option value="mobile">📱 手机端</option>
          <option value="desktop">💻 电脑端</option>
          <option value="web">🕸 网页端</option>
        </select>
      </div>
      <div class="m-grid-2" style="margin-bottom:6px">
        <input type="text" class="pc-name" placeholder="名称" />
        <input type="text" class="pc-user" placeholder="账号" />
      </div>
      <input type="text" class="pc-pwd" placeholder="密码" />
    `;
    const chk = card.querySelector(".pc-chk");
    chk.checked = row.selected !== false;
    chk.addEventListener("change", () => {
      row.selected = chk.checked;
    });

    const sc = card.querySelector(".pc-scope");
    sc.value = row.pwdsvScope || "universal";
    sc.addEventListener("change", () => {
      row.pwdsvScope = sc.value;
    });

    const nm = card.querySelector(".pc-name");
    nm.value = row.name || "";
    nm.addEventListener("input", () => {
      row.name = nm.value;
    });

    const us = card.querySelector(".pc-user");
    us.value = row.username || "";
    us.addEventListener("input", () => {
      row.username = us.value;
    });

    const pw = card.querySelector(".pc-pwd");
    pw.value = row.password || "";
    pw.addEventListener("input", () => {
      row.password = pw.value;
    });

    container.appendChild(card);
  });
}

$("m-batch-scope").addEventListener("change", (e) => {
  const val = e.target.value;
  if (!val) return;
  state.previewItems.forEach((r) => {
    if (r.selected !== false) r.pwdsvScope = val;
  });
  e.target.value = "";
  renderMobilePreviewCards();
});

$("btn-m-commit-import").addEventListener("click", async () => {
  const chosen = state.previewItems.filter((r) => r.selected !== false && (r.password || r.username));
  if (!chosen.length) {
    toast("请至少勾选一条要上传的密码");
    return;
  }

  const btn = $("btn-m-commit-import");
  btn.disabled = true;
  try {
    const token = await ensureToken();
    const api = makeApi(state.session.serverUrl, state.session.insecureTls);
    const toCreate = [];

    for (const row of chosen) {
      if (row.duplicateAction === "update" && row.existingId) {
        const ex = state.items.find((i) => i.id === row.existingId);
        if (ex) {
          const p = await buildLoginCipherPayload(
            {
              name: row.name,
              username: row.username,
              password: row.password,
              uris: row.uris?.length ? row.uris : ex.uris,
              pwdsvScope: row.pwdsvScope || "universal",
              pwdsvOriginDevice: "mobile-ai",
            },
            { userKey: state.session.userKey, userId: state.session.userId, keyId: state.session.keyId, existingItem: ex },
          );
          await api.updateCipher(token, ex.id, p);
          continue;
        }
      }
      toCreate.push(
        await buildLoginCipherPayload(
          {
            name: row.name,
            username: row.username,
            password: row.password,
            uris: row.uris || [],
            notes: row.notes || "",
            pwdsvScope: row.pwdsvScope || "universal",
            pwdsvOriginDevice: "mobile-ai",
          },
          { userKey: state.session.userKey, userId: state.session.userId, keyId: state.session.keyId },
        ),
      );
    }

    if (toCreate.length) {
      await api.importCiphers(token, { ciphers: toCreate, folders: [], folderRelationships: [] });
    }
    state.previewItems = [];
    $("m-preview-box").hidden = true;
    setMobileAiStep(1);
    await syncVault(true);
    switchTab("vault");
    toast(`已加密上传 ${chosen.length} 条密码！`);
  } catch (err) {
    toast("上传失败：" + err.message);
  } finally {
    btn.disabled = false;
  }
});

/* ------------------------------------------- 设置、应用内一键更新与 AI 模型提供商管理 */

function getMobileAppVersion() {
  if (native && typeof native.getAppVersionJson === "function") {
    try {
      const info = JSON.parse(native.getAppVersionJson() || "{}");
      return {
        versionName: info.versionName || "2.0.2",
        versionCode: Number(info.versionCode || 202),
      };
    } catch {
      /* 忽略 */
    }
  }
  return { versionName: "2.0.2", versionCode: 202 };
}

window.__pwdsvUpdateProgress = (pct) => {
  const bar = $("mu-progress-bar");
  const info = $("mu-info");
  if ($("mu-progress-wrap")) $("mu-progress-wrap").hidden = false;
  if (bar) bar.style.width = `${Math.max(0, Math.min(100, Number(pct) || 0))}%`;
  if (info) {
    info.hidden = false;
    info.textContent = `正在下载更新包… ${pct}%`;
  }
};

async function checkMobileUpdate(silent = false) {
  const ver = getMobileAppVersion();
  if ($("mu-cur-ver")) $("mu-cur-ver").textContent = `v${ver.versionName}`;
  const customUrl = ($("mu-manifest-url")?.value ?? secureGet("update_manifest_url") ?? "").trim();
  if ($("mu-manifest-url") && !$("mu-manifest-url").value && customUrl) {
    $("mu-manifest-url").value = customUrl;
  }

  const infoEl = $("mu-info");
  const installBtn = $("btn-mu-install");
  const dot = $("m-tab-settings-dot");
  if (!silent && infoEl) {
    infoEl.hidden = false;
    infoEl.textContent = "正在检查服务端更新清单…";
  }

  try {
    const res = await checkClientUpdate({
      platform: "mobile",
      currentVersion: ver.versionName,
      currentVersionCode: ver.versionCode,
      serverUrl: state.session?.serverUrl || "",
      customManifestUrl: customUrl,
      fetchImpl: makeMobileFetch(Boolean(state.session?.insecureTls)),
    });
    state.pendingUpdate = res.hasUpdate ? res : null;
    if (dot) dot.hidden = !res.hasUpdate;

    if (res.hasUpdate) {
      if (infoEl) {
        infoEl.hidden = false;
        infoEl.textContent = `发现新版 v${res.latestVersion}${res.notes ? ` · ${res.notes}` : ""}`;
      }
      if (installBtn) {
        installBtn.hidden = false;
        installBtn.textContent = `⬇ 一键下载并安装 v${res.latestVersion}`;
      }
    } else if (!silent) {
      if (infoEl) {
        infoEl.hidden = false;
        infoEl.textContent = `当前 v${ver.versionName} 已是最新版本`;
      }
      if (installBtn) installBtn.hidden = true;
    }
    return res;
  } catch (err) {
    if (!silent && infoEl) {
      infoEl.hidden = false;
      infoEl.textContent = "检查更新失败：" + String(err.message || err);
    }
    return null;
  }
}

$("mu-manifest-url")?.addEventListener("change", () => {
  secureSet("update_manifest_url", $("mu-manifest-url").value.trim());
});

$("btn-mu-check")?.addEventListener("click", async () => {
  secureSet("update_manifest_url", ($("mu-manifest-url")?.value || "").trim());
  const btn = $("btn-mu-check");
  btn.disabled = true;
  try {
    await checkMobileUpdate(false);
  } finally {
    btn.disabled = false;
  }
});

$("btn-mu-install")?.addEventListener("click", async () => {
  const upd = state.pendingUpdate;
  if (!upd?.downloadUrl) return;
  if (!native || typeof native.downloadAndInstallUpdateAsync !== "function") {
    window.open(upd.downloadUrl, "_blank");
    return;
  }
  const btn = $("btn-mu-install");
  const infoEl = $("mu-info");
  btn.disabled = true;
  if ($("mu-progress-wrap")) $("mu-progress-wrap").hidden = false;
  if ($("mu-progress-bar")) $("mu-progress-bar").style.width = "0%";
  if (infoEl) {
    infoEl.hidden = false;
    infoEl.textContent = "正在连接服务器下载安装包…";
  }

  try {
    const res = await callNativeAsync((cbId) =>
      native.downloadAndInstallUpdateAsync(
        cbId,
        JSON.stringify({
          url: upd.downloadUrl,
          sha256: upd.sha256 || "",
          insecureTls: Boolean(state.session?.insecureTls),
        }),
      ),
    );
    if (!res?.ok) throw new Error(res?.error || "更新失败");
    if (res.needsPermission) {
      infoEl.textContent = res.message || "请在系统设置允许安装应用，返回后再点一次即可安装";
      toast("请在系统设置中授权安装未知应用后返回");
    } else {
      infoEl.textContent = "校验通过，已调起系统安装器…";
    }
  } catch (err) {
    infoEl.textContent = "更新失败：" + String(err.message || err);
    toast("更新失败：" + String(err.message || err));
  } finally {
    btn.disabled = false;
  }
});

$("btn-m-autofill-sys").addEventListener("click", () => {
  if (native) native.openAutofillSettings();
  else toast("请在 Android 手机安装 APK 后点击跳转系统自动填充设置");
});

let editingMobProvId = null;

function populateProviderSettingsUI() {
  const ver = getMobileAppVersion();
  if ($("mu-cur-ver")) $("mu-cur-ver").textContent = `v${ver.versionName}`;
  if ($("mu-manifest-url")) $("mu-manifest-url").value = secureGet("update_manifest_url") || "";
  if (state.pendingUpdate?.hasUpdate) {
    if ($("mu-info")) {
      $("mu-info").hidden = false;
      $("mu-info").textContent = `发现新版 v${state.pendingUpdate.latestVersion}${state.pendingUpdate.notes ? ` · ${state.pendingUpdate.notes}` : ""}`;
    }
    if ($("btn-mu-install")) {
      $("btn-mu-install").hidden = false;
      $("btn-mu-install").textContent = `⬇ 一键下载并安装 v${state.pendingUpdate.latestVersion}`;
    }
  }
  const listSel = $("mp-list");
  listSel.textContent = "";
  for (const p of state.providers) {
    const opt = document.createElement("option");
    opt.value = p.id;
    opt.textContent = (p.id === state.activeProviderId ? "● " : "") + p.name;
    listSel.appendChild(opt);
  }

  const presetSel = $("mp-preset");
  presetSel.textContent = "";
  const hintOpt = document.createElement("option");
  hintOpt.value = "";
  hintOpt.textContent = "套用模板…";
  presetSel.appendChild(hintOpt);
  for (const tpl of PRESET_PROVIDERS) {
    const opt = document.createElement("option");
    opt.value = tpl.id;
    opt.textContent = tpl.name;
    presetSel.appendChild(opt);
  }

  editingMobProvId = state.activeProviderId || state.providers[0]?.id;
  listSel.value = editingMobProvId;
  loadProviderIntoMobileForm(state.providers.find((x) => x.id === editingMobProvId));
}

function resetMobileDetectedModels() {
  if ($("mp-models-datalist")) $("mp-models-datalist").textContent = "";
  if ($("mp-model-quick")) $("mp-model-quick").textContent = "";
  if ($("mp-model-picker-row")) $("mp-model-picker-row").hidden = true;
}

function loadProviderIntoMobileForm(p) {
  if (!p) return;
  $("mp-name").value = p.name || "";
  $("mp-proto").value = p.protocol || "openai-compatible";
  $("mp-url").value = p.baseUrl || "";
  $("mp-exact").checked = Boolean(p.exactEndpoint);
  $("mp-key").value = p.apiKey || "";
  $("mp-text-model").value = p.textModel || "";
  $("mp-vision-model").value = p.visionModel || "";
  $("mp-headers").value = p.customHeaders || "";
  if ($("mp-msg")) $("mp-msg").textContent = "";
  resetMobileDetectedModels();
}

let mobDetectTimer = null;
async function detectMobileProviderModels(silent = false) {
  const baseUrl = $("mp-url")?.value.trim() || "";
  if (!baseUrl) {
    if (!silent && $("mp-msg")) $("mp-msg").textContent = "请先填写 Base URL";
    return;
  }
  const msg = $("mp-msg");
  const btn = $("btn-mp-detect");
  const origBtn = btn?.textContent || "🔍 检测模型";
  if (!silent && msg) msg.textContent = "正在检测可用模型…";
  if (btn) {
    btn.disabled = true;
    btn.textContent = "检测中…";
  }
  try {
    const res = await fetchProviderModels(
      {
        protocol: $("mp-proto").value,
        baseUrl,
        exactEndpoint: Boolean($("mp-exact")?.checked),
        apiKey: $("mp-key").value.trim(),
        customHeaders: $("mp-headers").value.trim(),
      },
      { fetchImpl: makeMobileFetch(Boolean(state.session?.insecureTls)) },
    );
    const dl = $("mp-models-datalist");
    const sel = $("mp-model-quick");
    if (dl) {
      dl.textContent = "";
      for (const id of res.models) {
        const opt = document.createElement("option");
        opt.value = id;
        dl.appendChild(opt);
      }
    }
    if (sel) {
      sel.textContent = "";
      for (const id of res.models) {
        const opt = document.createElement("option");
        opt.value = id;
        opt.textContent = id;
        sel.appendChild(opt);
      }
      if (res.suggestedText) sel.value = res.suggestedText;
    }
    if ($("mp-model-picker-row")) $("mp-model-picker-row").hidden = !res.models.length;
    if (!$("mp-text-model").value.trim() && res.suggestedText) $("mp-text-model").value = res.suggestedText;
    if (!$("mp-vision-model").value.trim() && res.suggestedVision) $("mp-vision-model").value = res.suggestedVision;
    if (msg) msg.textContent = `✓ 检测到 ${res.models.length} 个模型（已自动填入推荐模型）`;
  } catch (err) {
    if (!silent && msg) msg.textContent = "✗ 模型检测失败：" + (err?.message || err);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = origBtn;
    }
  }
}

function scheduleMobileModelDetect() {
  if (mobDetectTimer) clearTimeout(mobDetectTimer);
  const url = $("mp-url")?.value.trim() || "";
  const key = $("mp-key")?.value.trim() || "";
  if (!/^https?:\/\/\S+/i.test(url)) return;
  if (!key && !/localhost|127\.0\.0\.1|10\.0\.2\.2|:11434/i.test(url)) return;
  mobDetectTimer = setTimeout(() => {
    mobDetectTimer = null;
    detectMobileProviderModels(true);
  }, 700);
}

$("btn-mp-detect")?.addEventListener("click", () => detectMobileProviderModels(false));
$("mp-url")?.addEventListener("input", scheduleMobileModelDetect);
$("mp-key")?.addEventListener("input", scheduleMobileModelDetect);
$("mp-proto")?.addEventListener("change", scheduleMobileModelDetect);
$("btn-mp-use-text")?.addEventListener("click", () => {
  const v = $("mp-model-quick")?.value;
  if (v) $("mp-text-model").value = v;
});
$("btn-mp-use-vision")?.addEventListener("click", () => {
  const v = $("mp-model-quick")?.value;
  if (v) $("mp-vision-model").value = v;
});

$("mp-list").addEventListener("change", () => {
  editingMobProvId = $("mp-list").value;
  loadProviderIntoMobileForm(state.providers.find((x) => x.id === editingMobProvId));
});

$("mp-preset").addEventListener("change", (e) => {
  const tpl = PRESET_PROVIDERS.find((x) => x.id === e.target.value);
  e.target.value = "";
  if (!tpl) return;
  editingMobProvId = "mob-" + tpl.id + "-" + Date.now();
  loadProviderIntoMobileForm({ ...tpl, apiKey: "", customHeaders: "" });
});

$("btn-mp-custom").addEventListener("click", () => {
  editingMobProvId = "mob-custom-" + Date.now();
  loadProviderIntoMobileForm({
    name: "我的自定义模型源",
    protocol: "openai-compatible",
    baseUrl: "",
    exactEndpoint: false,
    apiKey: "",
    textModel: "",
    visionModel: "",
    customHeaders: "",
  });
});

function readMobileProviderForm() {
  return {
    id: editingMobProvId || "mob-custom-" + Date.now(),
    name: $("mp-name").value.trim(),
    protocol: $("mp-proto").value,
    baseUrl: $("mp-url").value.trim(),
    exactEndpoint: $("mp-exact").checked,
    apiKey: $("mp-key").value.trim(),
    textModel: $("mp-text-model").value.trim(),
    visionModel: $("mp-vision-model").value.trim(),
    customHeaders: $("mp-headers").value.trim(),
  };
}

$("mp-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const cfg = readMobileProviderForm();
  const idx = state.providers.findIndex((p) => p.id === cfg.id);
  if (idx >= 0) state.providers[idx] = cfg;
  else state.providers.push(cfg);
  state.activeProviderId = cfg.id;
  saveMobileProviders();
  populateProviderSettingsUI();
  toast(`已启用模型源：${cfg.name}`);
});

$("btn-mp-test").addEventListener("click", async () => {
  const msg = $("mp-msg");
  msg.textContent = "测试连接中…";
  try {
    const res = await testProviderConnection(readMobileProviderForm(), {
      fetchImpl: makeMobileFetch(Boolean(state.session?.insecureTls)),
    });
    msg.textContent = "✓ 连通成功：" + res.sample;
  } catch (err) {
    msg.textContent = "✗ 失败：" + err.message;
  }
});

/* ------------------------------------------------------------------ 启动 */
loadMobileProviders();
showAuthView(true);
