/**
 * PWDSV Windows 桌面客户端主应用逻辑 v2.1：
 * - 四态密码作用域体系（🌐 三端通用 / 💻 电脑端 / 🕸 网页端 / 📱 手机端）
 * - 多格式文件识别与 AI 密码解析导入台（CSV / Excel .xlsx / Word .docx / PDF / TXT / 图片截图粘贴）
 * - 可自由切换 & 新增任意自定义模型提供商（API Key 经 Windows DPAPI 加密存本机，不经过 PWDSV 服务器）
 * - Win32 前台软件启动监听 + 无焦点 HUD 提示 + SendInput 键入 + 防 Win+V 泄漏安全剪贴板 + 本地短 PIN 快解
 */

import { PwdsvApi, ApiError, parseTwoFactorProviders, normalizeServerUrl } from "./lib/api.js";
import { deriveMasterKey, hashMasterPassword, SymmetricCryptoKey, encryptText } from "./lib/crypto.js";
import { unlockUserKey, decryptSync, buildLoginCipherPayload } from "./lib/vault.js";
import { generateTotp, parseTotp } from "./lib/totp.js";
import {
  matchesApp,
  hasAppUri,
  parseAppUri,
  resolveItemScope,
  isScopeApplicable,
  SCOPE_LABELS,
} from "./lib/matcher.js";
import { generatePassword, estimateStrength } from "./lib/generator.js";
import { RealtimeHub } from "./lib/realtime.js";
import {
  PRESET_PROVIDERS,
  parsePasswordFile,
  testProviderConnection,
  fetchProviderModels,
} from "./lib/importer/index.js";
import { checkClientUpdate } from "./lib/updater.js";

const invoke = (cmd, args = {}) => window.__TAURI__.core.invoke(cmd, args);
const listen = (event, handler) => window.__TAURI__.event.listen(event, handler);

const LOCAL_PREFS_KEY = "pwdsv_desktop_prefs_v2";
const DEFAULT_PREFS = {
  serverUrl: "",
  email: "",
  deviceId: "",
  insecureTls: false,
  watchEnabled: true,
  lockMinutes: 30,
  clipboardClearSeconds: 30,
  updateManifestUrl: "",
};

function loadPrefs() {
  try {
    const raw = JSON.parse(localStorage.getItem(LOCAL_PREFS_KEY) || "{}");
    const prefs = { ...DEFAULT_PREFS, ...raw };
    if (!prefs.deviceId) {
      prefs.deviceId = crypto.randomUUID();
      localStorage.setItem(LOCAL_PREFS_KEY, JSON.stringify(prefs));
    }
    return prefs;
  } catch {
    const prefs = { ...DEFAULT_PREFS, deviceId: crypto.randomUUID() };
    localStorage.setItem(LOCAL_PREFS_KEY, JSON.stringify(prefs));
    return prefs;
  }
}

function savePrefs(patch) {
  const next = { ...state.prefs, ...patch };
  state.prefs = next;
  localStorage.setItem(LOCAL_PREFS_KEY, JSON.stringify(next));
  return next;
}

function makeTauriFetch(insecureTls = false) {
  return async (url, init = {}) => {
    const res = await invoke("http_request", {
      req: {
        url: String(url),
        method: init.method || "GET",
        headers: init.headers || {},
        body: init.body !== undefined ? String(init.body) : null,
        insecureTls: Boolean(insecureTls),
      },
    });
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
  prefs: loadPrefs(),
  session: null,
  items: [],
  folders: [],
  domains: null,
  filter: "all", // all | universal | desktop | web | mobile | fav | folder:<id>
  selectedId: null,
  editingId: null,
  revealed: false,
  totpTimer: null,
  authPaneTimer: null,
  authCardRefs: [],
  idleTimer: null,
  hasPinConfigured: false,
  pinMeta: null,

  // AI 模型提供商（DPAPI 存本机）与预览导入缓存
  providers: [],
  activeProviderId: "",
  editingProviderId: null,
  previewItems: [],
  pendingUpdate: null,
};

/* ------------------------------------------------------------------ 实时同步 */

const realtimeHub = new RealtimeHub({
  onSyncNeeded: async () => {
    if (!state.session) return;
    await syncVault(true);
  },
  onForceLogout: () => lockVault("收到服务端登出指令，已锁定"),
});

/* ------------------------------------------------------------------ UI 工具 */

let toastTimeout = null;
function showToast(msg) {
  const bar = $("toast-bar");
  bar.textContent = msg;
  bar.hidden = false;
  if (toastTimeout) clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => { bar.hidden = true; }, 3500);
}

function touchActivity() {
  if (!state.session) return;
  if (state.idleTimer) clearTimeout(state.idleTimer);
  const mins = Number(state.prefs.lockMinutes || 0);
  if (mins > 0) {
    state.idleTimer = setTimeout(() => {
      lockVault("空闲超时，密码库已自动锁定");
    }, mins * 60000);
  }
}
["mousedown", "keydown"].forEach((ev) => document.addEventListener(ev, touchActivity, true));

function stopAuthPaneTimer() {
  if (state.authPaneTimer) clearInterval(state.authPaneTimer);
  state.authPaneTimer = null;
}

function showRightPane(which) {
  if (which !== "authenticator") stopAuthPaneTimer();
  for (const id of ["welcome", "detail", "authenticator", "editor", "importer", "providers", "settings"]) {
    $("pane-" + id).hidden = which !== id;
  }
}

/* ----------------------------------------------------- 视觉排版与密码语义着色 */

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

function applyAvatarVisual(el, name, idSeed) {
  if (!el) return;
  el.textContent = extractMonogram(name);
  el.style.background = avatarGradientFor(name || idSeed);
}

function formatTotpSpaced(code) {
  const s = String(code || "").trim();
  if (s.length === 6) return `${s.slice(0, 3)} ${s.slice(3)}`;
  if (s.length === 8) return `${s.slice(0, 4)} ${s.slice(4)}`;
  return s;
}

function renderPasswordValue(container, password, revealed) {
  container.textContent = "";
  if (!revealed) {
    container.className = "fg-value pwd-masked";
    container.textContent = "••••••••••••••";
    return;
  }
  container.className = "fg-value";
  if (!password) {
    container.textContent = "—";
    return;
  }
  for (const ch of Array.from(password)) {
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

function renderStrengthBadge(el, password, baseClass = "strength-pill") {
  if (!el) return;
  if (!password) {
    el.hidden = true;
    el.textContent = "";
    return;
  }
  const { score, label, entropy } = estimateStrength(password);
  const tier = score <= 1 ? "strength-weak" : score === 2 ? "strength-mid" : "strength-strong";
  el.hidden = false;
  el.className = `${baseClass} ${tier}`;
  el.textContent = `${label} · ${entropy} bit`;
}

function setImporterStep(step) {
  const pills = document.querySelectorAll("#pane-importer .stepper-bar .step-pill");
  pills.forEach((p, idx) => {
    p.classList.toggle("active", idx + 1 === step);
  });
}

function makeApiClient(serverUrl, insecureTls) {
  return new PwdsvApi(normalizeServerUrl(serverUrl), {
    deviceId: state.prefs.deviceId,
    deviceName: "KeyNexus Windows",
    deviceType: 6, // 6 = Windows Desktop
    clientName: "desktop",
    fetchImpl: makeTauriFetch(insecureTls),
  });
}

async function ensureAccessToken() {
  const s = state.session;
  if (!s) throw new Error("密码库已锁定");
  if (s.accessToken && Date.now() < (s.tokenExpiresAt || 0)) return s.accessToken;
  const api = makeApiClient(s.serverUrl, s.insecureTls);
  const t = await api.refresh(s.refreshToken);
  s.accessToken = t.accessToken;
  s.refreshToken = t.refreshToken;
  s.tokenExpiresAt = Date.now() + (t.expiresIn || 3600) * 1000 - 60000;
  realtimeHub.connect(s.serverUrl, s.accessToken);
  return s.accessToken;
}

function getTriggerRule(item) {
  const f = (item?.fields || []).find((x) => x.name === "_pwdsv_trigger");
  return f?.value || "launch";
}

async function pushWatchStateToRust() {
  const unlocked = Boolean(state.session);
  const watchEnabled = Boolean(state.prefs.watchEnabled);
  const pill = $("watch-indicator");
  pill.textContent = watchEnabled ? "● 守护中" : "○ 已暂停";
  pill.classList.toggle("off", !watchEnabled);

  const watchedApps = unlocked
    ? state.items
        .filter((it) => hasAppUri(it) && isScopeApplicable(resolveItemScope(it), "desktop"))
        .flatMap((it) =>
          (it.uris || [])
            .map((u) => parseAppUri(u.uri))
            .filter(Boolean)
            .map((r) => ({
              exe: r.exe.endsWith(".exe") ? r.exe : r.exe + ".exe",
              titlePattern: r.title || null,
              trigger: getTriggerRule(it),
            })),
        )
    : [];

  await invoke("update_watcher_state", { unlocked, watchEnabled, rules: watchedApps }).catch(() => {});
}

/* ----------------------------------------------------- 本机 AI 提供商存储 (DPAPI) */

function defaultProviderList() {
  return [
    { ...PRESET_PROVIDERS[0], id: "prov-deepseek", apiKey: "", customHeaders: "" },
    { ...PRESET_PROVIDERS[1], id: "prov-qwen", apiKey: "", customHeaders: "" },
    { ...PRESET_PROVIDERS[2], id: "prov-gemini", apiKey: "", customHeaders: "" },
    { ...PRESET_PROVIDERS[7], id: "prov-ollama", apiKey: "", customHeaders: "" },
  ];
}

async function loadAiProvidersFromDisk() {
  try {
    const jsonStr = await invoke("load_ai_providers_config");
    if (jsonStr) {
      const parsed = JSON.parse(jsonStr);
      if (Array.isArray(parsed.providers) && parsed.providers.length) {
        state.providers = parsed.providers;
        state.activeProviderId = parsed.activeProviderId || parsed.providers[0].id;
        return;
      }
    }
  } catch {
    /* 首次使用默认初始化 */
  }
  state.providers = defaultProviderList();
  state.activeProviderId = state.providers[0].id;
}

async function persistAiProvidersToDisk() {
  await invoke("save_ai_providers_config", {
    configJson: JSON.stringify({
      activeProviderId: state.activeProviderId,
      providers: state.providers,
    }),
  });
}

function getActiveProvider() {
  return state.providers.find((p) => p.id === state.activeProviderId) || state.providers[0] || null;
}

/* -------------------------------------------------------------- 登录与 PIN */

async function refreshPinStatus() {
  try {
    const res = await invoke("pin_vault_status");
    state.hasPinConfigured = Boolean(res?.configured);
    state.pinMeta = res || null;
  } catch {
    state.hasPinConfigured = false;
    state.pinMeta = null;
  }
}

function showUnlockForms(preferPin = true) {
  $("auth-screen").hidden = false;
  $("workspace").hidden = true;
  $("auth-server").value = state.prefs.serverUrl || "";
  $("auth-email").value = state.prefs.email || "";
  $("auth-insecure-tls").checked = Boolean(state.prefs.insecureTls);

  const usePin = preferPin && state.hasPinConfigured;
  $("pin-unlock-form").hidden = !usePin;
  $("master-unlock-form").hidden = usePin;
  $("pin-error").hidden = true;
  $("master-error").hidden = true;

  if (usePin) {
    $("pin-account-hint").textContent = `账号：${state.pinMeta?.email || state.prefs.email} · ${state.pinMeta?.serverUrl || state.prefs.serverUrl}`;
    $("pin-input").value = "";
    setTimeout(() => $("pin-input").focus(), 50);
  } else {
    setTimeout(() => (state.prefs.serverUrl ? $("auth-password") : $("auth-server")).focus(), 50);
  }
}

$("btn-switch-master").addEventListener("click", () => showUnlockForms(false));
$("auth-2fa-provider").addEventListener("change", () => {
  $("btn-auth-email-otp").hidden = Number($("auth-2fa-provider").value) !== 1;
});

$("btn-auth-email-otp").addEventListener("click", async () => {
  const btn = $("btn-auth-email-otp");
  btn.disabled = true;
  try {
    const serverUrl = normalizeServerUrl($("auth-server").value);
    const email = $("auth-email").value.trim();
    const password = $("auth-password").value;
    const api = makeApiClient(serverUrl, $("auth-insecure-tls").checked);
    const kdf = await api.prelogin(email);
    const mk = await deriveMasterKey(password, email, kdf);
    const hash = await hashMasterPassword(mk, password);
    await api.sendEmailLoginOtp({ email, masterPasswordHash: hash });
    showToast("已通知服务器发送邮件验证码");
  } catch (e) {
    $("master-error").hidden = false;
    $("master-error").textContent = String(e.message || e);
  } finally {
    btn.disabled = false;
  }
});

$("master-unlock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("btn-master-unlock");
  const errEl = $("master-error");
  errEl.hidden = true;
  btn.disabled = true;
  const origText = btn.textContent;
  btn.textContent = "正在派生主密钥并同步…";

  try {
    const serverUrl = normalizeServerUrl($("auth-server").value);
    const email = $("auth-email").value.trim();
    const password = $("auth-password").value;
    const insecureTls = $("auth-insecure-tls").checked;
    const setupPin = $("auth-setup-pin").value.trim();
    const api = makeApiClient(serverUrl, insecureTls);

    const kdf = await api.prelogin(email);
    const masterKey = await deriveMasterKey(password, email, kdf);
    const masterPasswordHash = await hashMasterPassword(masterKey, password);

    const has2faOpen = !$("auth-2fa-box").hidden;
    let tokens;
    try {
      tokens = await api.login({
        email,
        masterPasswordHash,
        twoFactorToken: has2faOpen ? $("auth-2fa-code").value.trim() || undefined : undefined,
        twoFactorProvider: has2faOpen ? Number($("auth-2fa-provider").value || 0) : 0,
      });
    } catch (loginErr) {
      if (loginErr instanceof ApiError && loginErr.status === 400) {
        const providers = parseTwoFactorProviders(loginErr);
        if (providers.length) {
          const sel = $("auth-2fa-provider");
          sel.textContent = "";
          for (const p of providers) {
            const opt = document.createElement("option");
            opt.value = String(p.id);
            opt.textContent = p.emailHint ? `${p.name} (${p.emailHint})` : p.name;
            sel.appendChild(opt);
          }
          $("btn-auth-email-otp").hidden = Number(sel.value) !== 1;
          $("auth-2fa-box").hidden = false;
          $("auth-2fa-code").focus();
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
    state.domains = vault.domains;

    savePrefs({ serverUrl, email, insecureTls });

    if (setupPin) {
      if (setupPin.length < 4) throw new Error("快捷 PIN 至少需要 4 位");
      await savePinBlob(setupPin);
      showToast("已解锁并启用本地快捷 PIN");
    } else {
      showToast(`已解锁密码库（共 ${vault.items.length} 条记录）`);
    }

    $("auth-password").value = "";
    $("auth-2fa-code").value = "";
    $("auth-setup-pin").value = "";
    $("auth-2fa-box").hidden = true;

    await enterWorkspace();
  } catch (err) {
    errEl.hidden = false;
    errEl.textContent = String(err.message || err);
  } finally {
    btn.disabled = false;
    btn.textContent = origText;
  }
});

async function savePinBlob(pin) {
  const s = state.session;
  if (!s) throw new Error("尚未解锁会话");
  const secretJson = JSON.stringify({
    userKeyB64: s.userKey.toB64(),
    userId: s.userId,
    keyId: s.keyId,
    email: s.email,
    serverUrl: s.serverUrl,
    insecureTls: s.insecureTls,
    refreshToken: s.refreshToken,
  });
  await invoke("save_pin_vault", {
    pin,
    email: s.email,
    serverUrl: s.serverUrl,
    secretJson,
  });
  await refreshPinStatus();
}

$("pin-unlock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("btn-pin-unlock");
  const errEl = $("pin-error");
  errEl.hidden = true;
  btn.disabled = true;

  try {
    const pin = $("pin-input").value.trim();
    const secretJson = await invoke("unlock_pin_vault", { pin });
    const data = JSON.parse(secretJson);

    const api = makeApiClient(data.serverUrl, data.insecureTls);
    const refreshed = await api.refresh(data.refreshToken);
    const userKey = SymmetricCryptoKey.fromB64(data.userKeyB64);
    const syncData = await api.sync(refreshed.accessToken);
    const vault = await decryptSync(syncData, userKey);

    state.session = {
      userKey,
      userId: syncData.profile?.id || data.userId,
      keyId: syncData.userDecryption?.userKeyId || data.keyId || null,
      email: data.email,
      serverUrl: data.serverUrl,
      insecureTls: Boolean(data.insecureTls),
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken,
      tokenExpiresAt: Date.now() + (refreshed.expiresIn || 3600) * 1000 - 60000,
    };
    state.items = vault.items;
    state.folders = vault.folders;
    state.domains = vault.domains;

    await savePinBlob(pin);
    $("pin-input").value = "";
    showToast("PIN 快捷解锁成功");
    await enterWorkspace();
  } catch (err) {
    await refreshPinStatus();
    if (!state.hasPinConfigured) {
      showUnlockForms(false);
      $("master-error").hidden = false;
      $("master-error").textContent = String(err.message || err);
    } else {
      errEl.hidden = false;
      errEl.textContent = String(err.message || err);
    }
  } finally {
    btn.disabled = false;
  }
});

async function enterWorkspace() {
  $("auth-screen").hidden = true;
  $("workspace").hidden = false;
  if ($("sidebar-user-email")) {
    $("sidebar-user-email").textContent = state.session?.email || "已加密连接";
  }
  touchActivity();
  realtimeHub.connect(state.session.serverUrl, state.session.accessToken);
  await pushWatchStateToRust();
  renderSidebarAndList();
  if (state.selectedId && state.items.some((i) => i.id === state.selectedId)) {
    openDetail(state.selectedId);
  } else {
    showRightPane("welcome");
  }
  checkDesktopUpdate(true).catch(() => {});
}

async function lockVault(reason = "密码库已锁定") {
  stopTotpTimer();
  stopAuthPaneTimer();
  if (state.idleTimer) clearTimeout(state.idleTimer);
  realtimeHub.disconnect();
  state.session = null;
  state.items = [];
  state.selectedId = null;
  state.previewItems = [];
  await pushWatchStateToRust();
  await invoke("hide_hud_window").catch(() => {});
  await refreshPinStatus();
  showUnlockForms(true);
  if (reason) showToast(reason);
}

async function syncVault(silent = false) {
  if (!state.session) return;
  try {
    const token = await ensureAccessToken();
    const api = makeApiClient(state.session.serverUrl, state.session.insecureTls);
    const data = await api.sync(token);
    const vault = await decryptSync(data, state.session.userKey);
    state.items = vault.items;
    state.folders = vault.folders;
    state.domains = vault.domains;
    await pushWatchStateToRust();
    renderSidebarAndList();
    if (state.selectedId) {
      const stillThere = state.items.find((i) => i.id === state.selectedId);
      if (stillThere && !$("pane-detail").hidden) openDetail(stillThere.id);
    }
    if (!$("pane-authenticator").hidden) renderDesktopAuthCards();
    if (!silent) showToast(`同步完成，共 ${state.items.length} 条密码`);
  } catch (e) {
    if (!silent) showToast("同步失败：" + e.message);
  }
}

/* ---------------------------------------------------------- 四态列表与筛选 */

function scopeBadgeClass(scope) {
  if (scope === "desktop") return "badge app";
  if (scope === "web") return "badge web";
  if (scope === "mobile") return "badge mobile";
  return "badge universal";
}

function filteredItems() {
  const q = $("vault-search").value.trim().toLowerCase();
  let list = [...state.items];

  if (["universal", "desktop", "web", "mobile"].includes(state.filter)) {
    list = list.filter((it) => resolveItemScope(it) === state.filter);
  } else if (state.filter === "fav") {
    list = list.filter((it) => it.favorite);
  } else if (state.filter === "totp") {
    list = list.filter((it) => Boolean(it.totp && String(it.totp).trim()));
  } else if (state.filter.startsWith("folder:")) {
    const fid = state.filter.slice("folder:".length);
    list = list.filter((it) => (it.folderId || "") === fid);
  }

  if (q) {
    list = list.filter((it) =>
      [it.name, it.username, it.notes, it.folderName, ...(it.uris || []).map((u) => u.uri)]
        .join(" ")
        .toLowerCase()
        .includes(q),
    );
  }

  return list.sort((a, b) => {
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
    return String(a.name || "").localeCompare(String(b.name || ""), "zh-CN");
  });
}

const SHORT_SCOPE_TEXT = {
  universal: "通用",
  desktop: "电脑",
  web: "网页",
  mobile: "手机",
};

const FILTER_TITLES = {
  all: "全部密码",
  universal: "🌐 三端通用账户",
  desktop: "💻 电脑端专属",
  web: "🕸 网页端专属",
  mobile: "📱 手机端专属",
  fav: "★ 星标收藏",
  totp: "⏱ Authenticator 验证器",
};

function renderSidebarAndList() {
  const counts = { universal: 0, desktop: 0, web: 0, mobile: 0 };
  for (const it of state.items) {
    const sc = resolveItemScope(it);
    counts[sc] = (counts[sc] || 0) + 1;
  }
  $("cnt-all").textContent = String(state.items.length);
  $("cnt-universal").textContent = String(counts.universal);
  $("cnt-desktop").textContent = String(counts.desktop);
  $("cnt-web").textContent = String(counts.web);
  $("cnt-mobile").textContent = String(counts.mobile);
  $("cnt-fav").textContent = String(state.items.filter((i) => i.favorite).length);
  if ($("cnt-totp")) {
    $("cnt-totp").textContent = String(state.items.filter((i) => Boolean(i.totp && String(i.totp).trim())).length);
  }

  if ($("dash-cnt-uni")) $("dash-cnt-uni").textContent = String(counts.universal);
  if ($("dash-cnt-desk")) $("dash-cnt-desk").textContent = String(counts.desktop);
  if ($("dash-cnt-web")) $("dash-cnt-web").textContent = String(counts.web);
  if ($("dash-cnt-mob")) $("dash-cnt-mob").textContent = String(counts.mobile);

  const fNav = $("folders-nav");
  fNav.textContent = "";
  for (const f of state.folders) {
    const btn = document.createElement("button");
    btn.type = "button";
    const key = "folder:" + f.id;
    btn.className = "nav-item" + (state.filter === key ? " active" : "");
    const count = state.items.filter((i) => i.folderId === f.id).length;
    const lbl = document.createElement("span");
    lbl.className = "nav-lbl";
    lbl.textContent = "📁 " + (f.name || "未命名");
    const em = document.createElement("em");
    em.textContent = String(count);
    btn.append(lbl, em);
    btn.addEventListener("click", () => {
      state.filter = key;
      syncActiveNav();
      renderListOnly();
    });
    fNav.appendChild(btn);
  }
  syncActiveNav();
  renderListOnly();
}

function syncActiveNav() {
  document.querySelectorAll(".sidebar .nav-item[data-filter]").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.filter === state.filter);
  });
}

document.querySelectorAll(".sidebar .nav-item[data-filter]").forEach((btn) => {
  btn.addEventListener("click", () => {
    state.filter = btn.dataset.filter;
    renderSidebarAndList();
    if (state.filter === "totp") {
      openAuthenticatorPane();
    }
  });
});

document.querySelectorAll(".stat-tile[data-jump]").forEach((tile) => {
  tile.addEventListener("click", () => {
    state.filter = tile.dataset.jump || "all";
    renderSidebarAndList();
  });
});

function currentFilterTitle() {
  if (FILTER_TITLES[state.filter]) return FILTER_TITLES[state.filter];
  if (state.filter.startsWith("folder:")) {
    const fid = state.filter.slice("folder:".length);
    const f = state.folders.find((x) => x.id === fid);
    return f ? `📁 ${f.name}` : "文件夹";
  }
  return "全部密码";
}

function renderListOnly() {
  const list = filteredItems();
  const ul = $("vault-list");
  ul.textContent = "";
  $("vault-empty").hidden = list.length > 0;
  if ($("list-filter-title")) $("list-filter-title").textContent = currentFilterTitle();
  if ($("list-result-count")) $("list-result-count").textContent = `${list.length} 项`;

  for (const item of list) {
    const li = document.createElement("li");
    if (item.id === state.selectedId) li.classList.add("active");
    li.addEventListener("click", () => openDetail(item.id));

    const avatar = document.createElement("div");
    avatar.className = "squircle-avatar";
    applyAvatarVisual(avatar, item.name || item.username, item.id);

    const main = document.createElement("div");
    main.className = "row-main";

    const top = document.createElement("div");
    top.className = "row-top";
    const title = document.createElement("span");
    title.className = "row-title-txt";
    title.textContent = (item.favorite ? "★ " : "") + (item.name || "(未命名)");
    top.appendChild(title);

    const sub = document.createElement("div");
    sub.className = "row-sub";
    sub.textContent = item.username || item.uris?.[0]?.uri || "无用户名";
    main.append(top, sub);

    const sc = resolveItemScope(item);
    const b = document.createElement("span");
    b.className = `${scopeBadgeClass(sc)} row-scope-badge`;
    b.textContent = SHORT_SCOPE_TEXT[sc] || "通用";

    const quickOps = document.createElement("div");
    quickOps.className = "row-quick-ops";

    if (item.password) {
      const btnType = document.createElement("button");
      btnType.type = "button";
      btnType.className = "micro-btn";
      btnType.title = "一键键入密码到上一窗口";
      btnType.textContent = "⌨ 键入";
      btnType.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        await invoke("auto_type_to_last_window", {
          username: item.username || "",
          password: item.password,
          includeUsername: false,
        });
        showToast(`已键入「${item.name}」的密码`);
      });

      const btnCopy = document.createElement("button");
      btnCopy.type = "button";
      btnCopy.className = "micro-btn";
      btnCopy.title = "一键安全复制密码";
      btnCopy.textContent = "复制";
      btnCopy.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        await secureCopy(item.password, `「${item.name}」密码`);
      });

      quickOps.append(btnType, btnCopy);
    }

    li.append(avatar, main, b, quickOps);
    ul.appendChild(li);
  }
}

$("vault-search").addEventListener("input", () => {
  renderListOnly();
  if (!$("pane-authenticator").hidden) renderDesktopAuthCards();
});
document.addEventListener("keydown", (e) => {
  if ($("workspace").hidden) return;
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "f") {
    e.preventDefault();
    $("vault-search").focus();
  } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "n") {
    e.preventDefault();
    openEditor(null);
  }
});

/* ---------------------------------------------------------- 详情与安全操作 */

function stopTotpTimer() {
  if (state.totpTimer) clearInterval(state.totpTimer);
  state.totpTimer = null;
}

function uriPlatformIcon(uri) {
  const u = String(uri || "");
  if (/^app:\/\//i.test(u)) return "💻";
  if (/^androidapp:\/\//i.test(u)) return "📱";
  return "🌐";
}

function openDetail(id) {
  stopTotpTimer();
  const item = state.items.find((i) => i.id === id);
  if (!item) return;
  state.selectedId = id;
  state.revealed = false;
  $("btn-d-reveal").textContent = "显示";
  renderListOnly();
  showRightPane("detail");

  applyAvatarVisual($("d-avatar"), item.name || item.username, item.id);
  $("d-name").textContent = item.name || "(未命名)";
  if ($("btn-d-fav")) {
    $("btn-d-fav").textContent = item.favorite ? "★" : "☆";
    $("btn-d-fav").style.opacity = item.favorite ? "1" : "0.45";
  }

  const badges = $("d-badges");
  badges.textContent = "";

  const sc = resolveItemScope(item);
  const scBadge = document.createElement("span");
  scBadge.className = scopeBadgeClass(sc);
  scBadge.textContent = SCOPE_LABELS[sc] || "三端通用";
  badges.appendChild(scBadge);

  if (item.folderName) {
    const b = document.createElement("span");
    b.className = "badge";
    b.textContent = "📁 " + item.folderName;
    badges.appendChild(b);
  }
  if (item.pwdsvOriginDevice) {
    const o = document.createElement("span");
    o.className = "badge";
    o.textContent = `来源：${item.pwdsvOriginDevice}`;
    badges.appendChild(o);
  }
  if (item.passwordHistory?.length) {
    const b = document.createElement("span");
    b.className = "badge";
    b.textContent = `历史密码 ${item.passwordHistory.length} 条`;
    badges.appendChild(b);
  }

  $("d-username").textContent = item.username || "—";
  renderStrengthBadge($("d-strength-pill"), item.password, "strength-pill");
  renderPasswordValue($("d-password"), item.password, false);

  $("d-uris-row").hidden = !item.uris?.length;
  $("d-uris").textContent = "";
  for (const u of item.uris || []) {
    const chip = document.createElement("div");
    chip.className = "uri-chip";
    const ic = document.createElement("span");
    ic.textContent = uriPlatformIcon(u.uri);
    const txt = document.createElement("span");
    txt.textContent = u.uri;
    chip.append(ic, txt);
    $("d-uris").appendChild(chip);
  }

  $("d-notes-row").hidden = !item.notes;
  $("d-notes").textContent = item.notes || "";

  $("d-totp-row").hidden = !item.totp;
  if (item.totp) {
    const circumference = 56.55;
    const tick = async () => {
      try {
        const { code, remaining, period } = await generateTotp(item.totp);
        $("d-totp").textContent = formatTotpSpaced(code);
        $("d-totp-left").textContent = `${remaining}s`;
        const circle = $("d-totp-circle");
        if (circle) {
          const total = period || 30;
          const offset = circumference * (1 - remaining / total);
          circle.setAttribute("stroke-dashoffset", offset.toFixed(2));
          circle.style.stroke = remaining <= 5 ? "#f59e0b" : "#34d399";
        }
      } catch {
        $("d-totp").textContent = "格式无效";
        $("d-totp-left").textContent = "";
      }
    };
    tick();
    state.totpTimer = setInterval(tick, 1000);
  }
}

$("btn-d-fav")?.addEventListener("click", async () => {
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
        pwdsvOriginDevice: item.pwdsvOriginDevice || "desktop",
      },
      {
        userKey: state.session.userKey,
        userId: state.session.userId,
        keyId: state.session.keyId,
        existingItem: item,
      },
    );
    const token = await ensureAccessToken();
    const api = makeApiClient(state.session.serverUrl, state.session.insecureTls);
    await api.updateCipher(token, item.id, payload);
    await syncVault(true);
    showToast(nextFav ? "★ 已加入星标收藏" : "已取消星标收藏");
  } catch (err) {
    showToast("更新收藏失败：" + (err.message || err));
  }
});

$("btn-d-reveal").addEventListener("click", () => {
  const item = state.items.find((i) => i.id === state.selectedId);
  if (!item) return;
  state.revealed = !state.revealed;
  renderPasswordValue($("d-password"), item.password, state.revealed);
  $("btn-d-reveal").textContent = state.revealed ? "隐藏" : "显示";
});

async function secureCopy(text, label = "内容") {
  if (!text) return;
  const clearSeconds = Number(state.prefs.clipboardClearSeconds || 30);
  await invoke("copy_secret_secure", { text, clearSeconds });
  showToast(`${label}已安全复制（已屏蔽 Win+V 剪贴板历史，${clearSeconds}s 后自动清空）`);
}

document.querySelectorAll("[data-copy]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const item = state.items.find((i) => i.id === state.selectedId);
    if (!item) return;
    const f = btn.dataset.copy;
    if (f === "username") await secureCopy(item.username, "账号");
    else if (f === "password") await secureCopy(item.password, "密码");
    else if (f === "totp" && item.totp) {
      const { code } = await generateTotp(item.totp);
      await secureCopy(code, "验证码");
    }
  });
});

$("btn-d-autotype").addEventListener("click", async () => {
  const item = state.items.find((i) => i.id === state.selectedId);
  if (!item?.password) return;
  await invoke("auto_type_to_last_window", {
    username: item.username || "",
    password: item.password,
    includeUsername: false,
  });
  showToast("已向目标窗口键入密码");
});

$("btn-d-autotype-both").addEventListener("click", async () => {
  const item = state.items.find((i) => i.id === state.selectedId);
  if (!item?.password) return;
  await invoke("auto_type_to_last_window", {
    username: item.username || "",
    password: item.password,
    includeUsername: true,
  });
  showToast("已向目标窗口键入账号与密码");
});

$("btn-d-delete").addEventListener("click", async () => {
  const item = state.items.find((i) => i.id === state.selectedId);
  if (!item) return;
  if (!confirm(`确定要从服务器永久删除「${item.name}」吗？`)) return;
  const token = await ensureAccessToken();
  const api = makeApiClient(state.session.serverUrl, state.session.insecureTls);
  await api.deleteCipher(token, item.id);
  state.selectedId = null;
  await syncVault(true);
  showRightPane("welcome");
  showToast("已删除该密码记录");
});

/* -------------------------------------------------- 新建 / 编辑 / 绑定运行应用 */

async function refreshRunningAppsDropdown() {
  const sel = $("running-apps-select");
  sel.textContent = "";
  const def = document.createElement("option");
  def.value = "";
  def.textContent = "-- 从当前正在运行的 Windows 程序中点选添加 --";
  sel.appendChild(def);

  try {
    const apps = await invoke("list_running_apps");
    for (const app of apps || []) {
      const opt = document.createElement("option");
      opt.value = app.exe;
      opt.textContent = app.title ? `${app.exe}  —  ${app.title.slice(0, 38)}` : app.exe;
      sel.appendChild(opt);
    }
  } catch {
    /* 忽略 */
  }
}

$("btn-refresh-apps").addEventListener("click", refreshRunningAppsDropdown);

$("btn-add-app-rule").addEventListener("click", () => {
  const exe = $("running-apps-select").value;
  if (!exe) {
    showToast("请先从下拉框选择一个正在运行的程序");
    return;
  }
  const titleFilter = $("app-title-filter").value.trim();
  const rule = titleFilter
    ? `app://${exe}?title=${encodeURIComponent(titleFilter)}`
    : `app://${exe}`;

  const cur = $("f-uris").value.trim();
  $("f-uris").value = cur ? `${cur}\n${rule}` : rule;
  if (!$("f-name").value.trim()) $("f-name").value = exe.replace(/\.exe$/i, "");
  if ($("f-scope").value === "web" || $("f-scope").value === "mobile") {
    $("f-scope").value = "universal";
  }
  $("app-title-filter").value = "";
});

function populateEditorFolders(selectedId = "") {
  const sel = $("f-folder");
  sel.textContent = "";
  const none = document.createElement("option");
  none.value = "";
  none.textContent = "无文件夹";
  sel.appendChild(none);
  for (const f of state.folders) {
    const opt = document.createElement("option");
    opt.value = f.id;
    opt.textContent = f.name || "未命名";
    sel.appendChild(opt);
  }
  sel.value = selectedId || "";
}

async function openEditor(item = null, presetApp = null) {
  stopTotpTimer();
  $("ed-error").hidden = true;
  $("f-password").type = "password";
  $("btn-f-eye").textContent = "显示";
  populateEditorFolders(item?.folderId || "");
  await refreshRunningAppsDropdown();

  if (item) {
    state.editingId = item.id;
    $("ed-heading").textContent = `编辑密码：${item.name}`;
    $("f-name").value = item.name || "";
    $("f-scope").value = resolveItemScope(item);
    $("f-username").value = item.username || "";
    $("f-password").value = item.password || "";
    $("f-uris").value = (item.uris || []).map((u) => u.uri).join("\n");
    $("f-totp").value = item.totp || "";
    $("f-trigger").value = getTriggerRule(item);
    $("f-favorite").checked = Boolean(item.favorite);
    $("f-notes").value = item.notes || "";
  } else {
    state.editingId = null;
    $("ed-heading").textContent = "提交新密码";
    $("f-name").value = presetApp?.exe ? presetApp.exe.replace(/\.exe$/i, "") : "";
    const defaultScope = presetApp?.exe
      ? "desktop"
      : ["universal", "desktop", "web", "mobile"].includes(state.filter)
        ? state.filter
        : "universal";
    $("f-scope").value = defaultScope;
    $("f-username").value = "";
    $("f-password").value = "";
    $("f-uris").value = presetApp?.exe
      ? `app://${presetApp.exe}`
      : defaultScope === "desktop"
        ? "app://"
        : defaultScope === "mobile"
          ? "androidapp://"
          : "";
    $("f-totp").value = "";
    $("f-trigger").value = "launch";
    $("f-favorite").checked = false;
    $("f-notes").value = presetApp?.title ? `创建自窗口：${presetApp.title}` : "";
  }

  renderStrengthBadge($("f-pwd-strength"), $("f-password").value, "strength-inline");
  showRightPane("editor");
  ($("f-name").value ? $("f-username") : $("f-name")).focus();
}

$("btn-new-item").addEventListener("click", () => openEditor(null));
$("btn-empty-create").addEventListener("click", () => openEditor(null));
$("btn-empty-ai")?.addEventListener("click", openImporterPane);
$("btn-d-edit").addEventListener("click", () => {
  const item = state.items.find((i) => i.id === state.selectedId);
  if (item) openEditor(item);
});
$("btn-ed-cancel").addEventListener("click", () => {
  if (state.selectedId) openDetail(state.selectedId);
  else showRightPane("welcome");
});

$("f-password").addEventListener("input", () => {
  renderStrengthBadge($("f-pwd-strength"), $("f-password").value, "strength-inline");
});

$("btn-f-eye").addEventListener("click", () => {
  const hidden = $("f-password").type === "password";
  $("f-password").type = hidden ? "text" : "password";
  $("btn-f-eye").textContent = hidden ? "隐藏" : "显示";
});

$("btn-f-gen").addEventListener("click", () => {
  $("f-password").value = generatePassword({ length: 20, symbols: true });
  $("f-password").type = "text";
  $("btn-f-eye").textContent = "隐藏";
  renderStrengthBadge($("f-pwd-strength"), $("f-password").value, "strength-inline");
});

$("pane-editor").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("btn-f-submit");
  const errEl = $("ed-error");
  errEl.hidden = true;
  btn.disabled = true;

  try {
    const existingItem = state.editingId ? state.items.find((i) => i.id === state.editingId) : null;
    if (!$("f-password").value && !$("f-totp").value.trim()) {
      throw new Error("密码和 Authenticator 密钥不能同时为空");
    }
    const uris = $("f-uris").value
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map((uri) => ({ uri, match: null }));

    const otherFields = (existingItem?.fields || []).filter((f) => f.name !== "_pwdsv_trigger");
    const fields = [...otherFields, { name: "_pwdsv_trigger", value: $("f-trigger").value, type: 0 }];

    const payload = await buildLoginCipherPayload(
      {
        name: $("f-name").value.trim(),
        username: $("f-username").value.trim(),
        password: $("f-password").value,
        uris,
        totp: $("f-totp").value.trim(),
        folderId: $("f-folder").value || null,
        favorite: $("f-favorite").checked,
        notes: $("f-notes").value.trim(),
        fields,
        pwdsvScope: $("f-scope").value || "universal",
        pwdsvOriginDevice: "desktop",
      },
      {
        userKey: state.session.userKey,
        userId: state.session.userId,
        keyId: state.session.keyId,
        existingItem,
      },
    );

    const token = await ensureAccessToken();
    const api = makeApiClient(state.session.serverUrl, state.session.insecureTls);
    const saved = existingItem
      ? await api.updateCipher(token, existingItem.id, payload)
      : await api.createCipher(token, payload);

    await syncVault(true);
    openDetail(saved?.id || existingItem?.id);
    showToast(existingItem ? "修改已加密同步至服务器" : "新密码已加密提交至服务器");
  } catch (err) {
    errEl.hidden = false;
    errEl.textContent = String(err.message || err);
  } finally {
    btn.disabled = false;
  }
});

/* =================================================== Authenticator 独立动态码竖栏 */

async function refreshDesktopAuthCodes() {
  const circumference = 131.95;
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
        ref.codeEl.textContent = "密钥无效";
        ref.leftEl.textContent = "";
      }
    }),
  );
}

function renderDesktopAuthCards() {
  const q = ($("vault-search")?.value || "").trim().toLowerCase();
  let list = state.items.filter((it) => Boolean(it.totp && String(it.totp).trim()));
  if (q) {
    list = list.filter((it) =>
      [it.name, it.username, it.notes, it.folderName, ...(it.uris || []).map((u) => u.uri)]
        .join(" ")
        .toLowerCase()
        .includes(q),
    );
  }
  list.sort((a, b) => {
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
    return String(a.name || "").localeCompare(String(b.name || ""), "zh-CN");
  });

  const container = $("da-list");
  if (!container) return;
  container.textContent = "";
  state.authCardRefs = [];
  if ($("da-empty")) $("da-empty").hidden = list.length > 0;

  for (const item of list) {
    const card = document.createElement("div");
    card.className = "da-card";

    const accent = document.createElement("span");
    accent.className = "da-accent";
    accent.style.background = avatarGradientFor(item.name || item.id);

    const left = document.createElement("div");
    left.className = "da-card-left";

    const ringAvatar = document.createElement("div");
    ringAvatar.className = "da-ring-avatar";
    ringAvatar.innerHTML = `
      <svg class="da-ring-svg" viewBox="0 0 48 48" width="48" height="48">
        <circle class="ring-bg" cx="24" cy="24" r="21" />
        <circle class="ring-fg" cx="24" cy="24" r="21" stroke-dasharray="131.95" stroke-dashoffset="0" />
      </svg>
    `;
    const avatar = document.createElement("div");
    avatar.className = "squircle-avatar round";
    applyAvatarVisual(avatar, item.name || item.username, item.id);
    const leftEl = document.createElement("em");
    leftEl.className = "da-sec-badge";
    leftEl.textContent = "--";
    ringAvatar.append(avatar, leftEl);

    const circleEl = ringAvatar.querySelector(".ring-fg");

    const meta = document.createElement("div");
    meta.className = "da-card-meta";
    const titleLine = document.createElement("div");
    titleLine.className = "da-title-line";
    const nm = document.createElement("span");
    nm.className = "da-card-name";
    nm.textContent = (item.favorite ? "★ " : "") + (item.name || "(未命名)");
    const usr = document.createElement("span");
    usr.className = "da-card-user";
    usr.textContent = item.username || item.uris?.[0]?.uri || "验证器";
    titleLine.append(nm, usr);

    const codeEl = document.createElement("code");
    codeEl.className = "da-code";
    codeEl.textContent = "••• •••";

    meta.append(titleLine, codeEl);
    left.append(ringAvatar, meta);

    const right = document.createElement("div");
    right.className = "da-card-right";

    const ops = document.createElement("div");
    ops.className = "da-card-ops";

    const btnCopy = document.createElement("button");
    btnCopy.type = "button";
    btnCopy.className = "ghost small";
    btnCopy.textContent = "复制";

    const btnType = document.createElement("button");
    btnType.type = "button";
    btnType.className = "ghost small";
    btnType.title = "键入动态码到上一窗口";
    btnType.textContent = "⌨ 键入";

    const btnDetail = document.createElement("button");
    btnDetail.type = "button";
    btnDetail.className = "ghost small";
    btnDetail.textContent = "›";
    btnDetail.title = "查看详情";

    const ref = {
      id: item.id,
      name: item.name || "Authenticator",
      totp: item.totp,
      currentCode: "",
      codeEl,
      circleEl,
      leftEl,
    };

    const resolveCode = async () => {
      if (ref.currentCode) return ref.currentCode;
      const r = await generateTotp(item.totp);
      ref.currentCode = r.code;
      return r.code;
    };

    btnCopy.addEventListener("click", async () => {
      try {
        const code = await resolveCode();
        await secureCopy(code, `「${ref.name}」验证码`);
      } catch {
        showToast("Authenticator 密钥格式无效");
      }
    });

    btnType.addEventListener("click", async () => {
      try {
        const code = await resolveCode();
        await invoke("auto_type_to_last_window", {
          username: "",
          password: code,
          includeUsername: false,
        });
        showToast(`已键入「${ref.name}」验证码`);
      } catch {
        showToast("键入验证码失败");
      }
    });

    btnDetail.addEventListener("click", () => openDetail(item.id));

    ops.append(btnCopy, btnType, btnDetail);
    right.append(ops);
    card.append(accent, left, right);
    container.appendChild(card);
    state.authCardRefs.push(ref);
  }

  refreshDesktopAuthCodes();
}

function openAuthenticatorPane() {
  stopTotpTimer();
  stopAuthPaneTimer();
  showRightPane("authenticator");
  renderDesktopAuthCards();
  state.authPaneTimer = setInterval(refreshDesktopAuthCodes, 1000);
}

function toggleDesktopAuthAddForm(show) {
  const form = $("da-add-form");
  if (!form) return;
  const open = show !== undefined ? Boolean(show) : form.hidden;
  form.hidden = !open;
  if ($("da-add-err")) $("da-add-err").hidden = true;
  if (open) $("da-secret")?.focus();
}

$("btn-da-toggle-add")?.addEventListener("click", () => toggleDesktopAuthAddForm());
$("btn-da-cancel")?.addEventListener("click", () => toggleDesktopAuthAddForm(false));
$("btn-da-empty-add")?.addEventListener("click", () => toggleDesktopAuthAddForm(true));

$("da-secret")?.addEventListener("input", () => {
  const raw = $("da-secret").value.trim();
  if (!/^otpauth:\/\//i.test(raw)) return;
  try {
    const parsed = parseTotp(raw);
    if (parsed.issuer && !$("da-name").value.trim()) $("da-name").value = parsed.issuer;
    if (parsed.account && !$("da-user").value.trim()) $("da-user").value = parsed.account;
  } catch {
    /* 忽略输入过程中的临时解析失败 */
  }
});

$("da-add-form")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("btn-da-save");
  const errEl = $("da-add-err");
  errEl.hidden = true;
  btn.disabled = true;

  try {
    const secret = $("da-secret").value.trim();
    const name = $("da-name").value.trim();
    const username = $("da-user").value.trim();
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
        pwdsvOriginDevice: "desktop",
      },
      {
        userKey: state.session.userKey,
        userId: state.session.userId,
        keyId: state.session.keyId,
      },
    );

    const token = await ensureAccessToken();
    const api = makeApiClient(state.session.serverUrl, state.session.insecureTls);
    await api.createCipher(token, payload);

    $("da-add-form").reset();
    toggleDesktopAuthAddForm(false);
    await syncVault(true);
    renderDesktopAuthCards();
    showToast("Authenticator 验证器已加密保存到服务器");
  } catch (err) {
    errEl.hidden = false;
    errEl.textContent = String(err.message || err);
  } finally {
    btn.disabled = false;
  }
});

/* =================================================== AI 模型提供商管理中心 */

function renderProviderSelectorInImporter() {
  const sel = $("imp-provider-select");
  sel.textContent = "";
  for (const p of state.providers) {
    const opt = document.createElement("option");
    opt.value = p.id;
    const keyTag = p.apiKey || p.requiresKey === false ? "已配置" : "待填 Key";
    opt.textContent = `${p.name} · ${p.textModel || p.visionModel} [${keyTag}]`;
    sel.appendChild(opt);
  }
  if (state.activeProviderId) sel.value = state.activeProviderId;
}

$("imp-provider-select").addEventListener("change", async () => {
  state.activeProviderId = $("imp-provider-select").value;
  await persistAiProvidersToDisk().catch(() => {});
});

function populatePresetTemplates() {
  const sel = $("prov-preset-select");
  sel.textContent = "";
  for (const preset of PRESET_PROVIDERS) {
    const opt = document.createElement("option");
    opt.value = preset.id;
    opt.textContent = `${preset.name} (${preset.protocol})`;
    sel.appendChild(opt);
  }
}

function renderProvidersManagerList() {
  const ul = $("prov-list");
  ul.textContent = "";
  for (const p of state.providers) {
    const li = document.createElement("li");
    if (p.id === state.editingProviderId) li.classList.add("active");
    li.addEventListener("click", () => selectProviderForEdit(p.id));

    const top = document.createElement("div");
    top.className = "row-top";
    const nm = document.createElement("span");
    nm.textContent = (p.id === state.activeProviderId ? "● " : "") + p.name;
    top.appendChild(nm);

    const b = document.createElement("span");
    b.className = "badge";
    b.textContent = p.protocol === "gemini" ? "Gemini" : p.protocol === "anthropic" ? "Claude" : "OpenAI兼容";
    top.appendChild(b);

    const sub = document.createElement("div");
    sub.className = "row-sub";
    sub.textContent = `${p.textModel || "—"} · ${p.baseUrl}`;

    li.append(top, sub);
    ul.appendChild(li);
  }
}

function resetDesktopDetectedModels() {
  if ($("p-models-datalist")) $("p-models-datalist").textContent = "";
  if ($("p-model-quick")) $("p-model-quick").textContent = "";
  if ($("p-model-picker-row")) $("p-model-picker-row").hidden = true;
}

function selectProviderForEdit(id) {
  const p = state.providers.find((x) => x.id === id);
  if (!p) return;
  state.editingProviderId = p.id;
  $("p-name").value = p.name || "";
  $("p-protocol").value = p.protocol || "openai-compatible";
  $("p-baseurl").value = p.baseUrl || "";
  $("p-exact").checked = Boolean(p.exactEndpoint);
  $("p-apikey").value = p.apiKey || "";
  $("p-text-model").value = p.textModel || "";
  $("p-vision-model").value = p.visionModel || "";
  $("p-headers").value =
    typeof p.customHeaders === "string"
      ? p.customHeaders
      : p.customHeaders
        ? JSON.stringify(p.customHeaders)
        : "";
  $("prov-msg").textContent = "";
  resetDesktopDetectedModels();
  renderProvidersManagerList();
}

function openProvidersPane() {
  stopTotpTimer();
  populatePresetTemplates();
  if (!state.editingProviderId && state.providers[0]) {
    state.editingProviderId = state.activeProviderId || state.providers[0].id;
  }
  selectProviderForEdit(state.editingProviderId);
  showRightPane("providers");
}

$("btn-open-providers").addEventListener("click", openProvidersPane);
$("btn-imp-manage-providers").addEventListener("click", openProvidersPane);
$("btn-prov-back").addEventListener("click", openImporterPane);

$("btn-prov-new-custom").addEventListener("click", () => {
  state.editingProviderId = "custom-" + Date.now();
  $("p-name").value = "我的自定义模型网关";
  $("p-protocol").value = "openai-compatible";
  $("p-baseurl").value = "";
  $("p-exact").checked = false;
  $("p-apikey").value = "";
  $("p-text-model").value = "";
  $("p-vision-model").value = "";
  $("p-headers").value = "";
  $("prov-msg").textContent = "请填写自定义网关信息后点击保存";
  resetDesktopDetectedModels();
  renderProvidersManagerList();
  $("p-name").focus();
});

$("btn-prov-add-preset").addEventListener("click", () => {
  const tpl = PRESET_PROVIDERS.find((x) => x.id === $("prov-preset-select").value);
  if (!tpl) return;
  state.editingProviderId = "prov-" + tpl.id + "-" + Date.now();
  $("p-name").value = tpl.name;
  $("p-protocol").value = tpl.protocol;
  $("p-baseurl").value = tpl.baseUrl;
  $("p-exact").checked = false;
  $("p-apikey").value = "";
  $("p-text-model").value = tpl.textModel || "";
  $("p-vision-model").value = tpl.visionModel || "";
  $("p-headers").value = "";
  $("prov-msg").textContent = `已载入「${tpl.name}」模板，填入 API Key 即可保存`;
  resetDesktopDetectedModels();
});

let desktopDetectTimer = null;
async function detectDesktopProviderModels(silent = false) {
  const baseUrl = $("p-baseurl")?.value.trim() || "";
  if (!baseUrl) {
    if (!silent) $("prov-msg").textContent = "请先填写 API Base URL";
    return;
  }
  const msgEl = $("prov-msg");
  const btn = $("btn-prov-detect");
  const origBtn = btn?.textContent || "🔍 检测模型";
  if (!silent) msgEl.textContent = "正在检测可用模型…";
  if (btn) {
    btn.disabled = true;
    btn.textContent = "检测中…";
  }
  try {
    const res = await fetchProviderModels(
      {
        protocol: $("p-protocol").value,
        baseUrl,
        exactEndpoint: Boolean($("p-exact")?.checked),
        apiKey: $("p-apikey").value.trim(),
        customHeaders: $("p-headers").value.trim(),
      },
      { fetchImpl: makeTauriFetch(Boolean(state.session?.insecureTls ?? state.prefs.insecureTls)) },
    );
    const dl = $("p-models-datalist");
    const sel = $("p-model-quick");
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
    if ($("p-model-picker-row")) $("p-model-picker-row").hidden = !res.models.length;
    if (!$("p-text-model").value.trim() && res.suggestedText) $("p-text-model").value = res.suggestedText;
    if (!$("p-vision-model").value.trim() && res.suggestedVision) $("p-vision-model").value = res.suggestedVision;
    msgEl.textContent = `✓ 检测到 ${res.models.length} 个模型（已自动填入推荐模型，也可从下方列表切换）`;
  } catch (err) {
    if (!silent) msgEl.textContent = `✗ 模型检测失败：${err?.message || err}`;
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = origBtn;
    }
  }
}

function scheduleDesktopModelDetect() {
  if (desktopDetectTimer) clearTimeout(desktopDetectTimer);
  const url = $("p-baseurl")?.value.trim() || "";
  const key = $("p-apikey")?.value.trim() || "";
  if (!/^https?:\/\/\S+/i.test(url)) return;
  if (!key && !/localhost|127\.0\.0\.1|:11434/i.test(url)) return;
  desktopDetectTimer = setTimeout(() => {
    desktopDetectTimer = null;
    detectDesktopProviderModels(true);
  }, 700);
}

$("btn-prov-detect")?.addEventListener("click", () => detectDesktopProviderModels(false));
$("p-baseurl")?.addEventListener("input", scheduleDesktopModelDetect);
$("p-apikey")?.addEventListener("input", scheduleDesktopModelDetect);
$("p-protocol")?.addEventListener("change", scheduleDesktopModelDetect);
$("btn-p-use-text")?.addEventListener("click", () => {
  const v = $("p-model-quick")?.value;
  if (v) $("p-text-model").value = v;
});
$("btn-p-use-vision")?.addEventListener("click", () => {
  const v = $("p-model-quick")?.value;
  if (v) $("p-vision-model").value = v;
});

function collectProviderForm() {
  return {
    id: state.editingProviderId || "custom-" + Date.now(),
    name: $("p-name").value.trim(),
    protocol: $("p-protocol").value,
    baseUrl: $("p-baseurl").value.trim(),
    exactEndpoint: $("p-exact").checked,
    apiKey: $("p-apikey").value.trim(),
    textModel: $("p-text-model").value.trim(),
    visionModel: $("p-vision-model").value.trim(),
    customHeaders: $("p-headers").value.trim(),
  };
}

$("prov-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const cfg = collectProviderForm();
  const idx = state.providers.findIndex((p) => p.id === cfg.id);
  if (idx >= 0) state.providers[idx] = cfg;
  else state.providers.push(cfg);

  state.activeProviderId = cfg.id;
  state.editingProviderId = cfg.id;
  await persistAiProvidersToDisk();
  renderProvidersManagerList();
  renderProviderSelectorInImporter();
  $("prov-msg").textContent = "✓ 已加密保存到本机并设为当前使用的模型提供商";
  showToast(`已切换当前 AI 提供商为：${cfg.name}`);
});

$("btn-prov-test").addEventListener("click", async () => {
  const msgEl = $("prov-msg");
  msgEl.textContent = "正在直连测试模型接口…";
  try {
    const cfg = collectProviderForm();
    const res = await testProviderConnection(cfg, { fetchImpl: makeTauriFetch(false) });
    msgEl.textContent = `✓ 连通成功！模型响应：${res.sample}`;
  } catch (err) {
    msgEl.textContent = `✗ 测试失败：${err.message || err}`;
  }
});

$("btn-prov-delete").addEventListener("click", async () => {
  if (state.providers.length <= 1) {
    showToast("至少保留一个模型提供商配置");
    return;
  }
  state.providers = state.providers.filter((p) => p.id !== state.editingProviderId);
  state.activeProviderId = state.providers[0].id;
  state.editingProviderId = state.providers[0].id;
  await persistAiProvidersToDisk();
  selectProviderForEdit(state.editingProviderId);
  renderProviderSelectorInImporter();
  showToast("已删除该提供商配置");
});

/* ========================================== 多格式文件识别与 AI 导密工作台 */

function openImporterPane() {
  stopTotpTimer();
  renderProviderSelectorInImporter();
  setImporterStep(state.previewItems.length > 0 ? 3 : 1);
  showRightPane("importer");
}

$("btn-open-importer").addEventListener("click", openImporterPane);
$("btn-imp-pick-file").addEventListener("click", () => $("imp-file-input").click());
$("btn-imp-toggle-text").addEventListener("click", () => {
  $("imp-raw-text-box").hidden = !$("imp-raw-text-box").hidden;
});

/** 将大图在本地 Canvas 等比缩放至长边 ≤ 1600px，兼顾文字清晰度与 Vision 模型传输速度 */
async function downscaleImageIfNeeded(file) {
  if (!file.type.startsWith("image/")) {
    return { name: file.name, mimeType: file.type, bytes: new Uint8Array(await file.arrayBuffer()) };
  }
  const bitmap = await createImageBitmap(file);
  const maxDim = 1600;
  if (bitmap.width <= maxDim && bitmap.height <= maxDim) {
    return { name: file.name, mimeType: file.type, bytes: new Uint8Array(await file.arrayBuffer()) };
  }
  const ratio = Math.min(maxDim / bitmap.width, maxDim / bitmap.height);
  const canvas = document.createElement("canvas");
  canvas.width = Math.round(bitmap.width * ratio);
  canvas.height = Math.round(bitmap.height * ratio);
  const ctx = canvas.getContext("2d");
  ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  const blob = await new Promise((r) => canvas.toBlob(r, "image/jpeg", 0.9));
  return { name: file.name, mimeType: "image/jpeg", bytes: new Uint8Array(await blob.arrayBuffer()) };
}

async function runFileExtractionFlow(fileObj) {
  const statusEl = $("imp-status");
  const errEl = $("imp-error");
  errEl.hidden = true;
  statusEl.hidden = false;
  setImporterStep(2);

  try {
    const activeProv = getActiveProvider();
    const result = await parsePasswordFile(fileObj, {
      provider: activeProv,
      existingVaultItems: state.items,
      forceAi: $("imp-force-ai").checked,
      fetchImpl: makeTauriFetch(false),
      onProgress: (txt) => {
        statusEl.textContent = txt;
      },
    });

    state.previewItems = result.items || [];
    const modeName =
      result.mode === "fast-rule"
        ? "本地标准表头秒解（0 Token）"
        : result.mode === "ai-vision"
          ? `AI 视觉识别 (${activeProv?.name})`
          : `AI 智能语义解析 (${activeProv?.name})`;

    statusEl.textContent = `✓ 解析完成 [${modeName}]：从「${result.fileName}」提取出 ${state.previewItems.length} 条密码记录，请核对下方列表后加密上传。`;
    setImporterStep(state.previewItems.length > 0 ? 3 : 1);
    renderPreviewTable();
  } catch (err) {
    setImporterStep(1);
    statusEl.hidden = true;
    errEl.hidden = false;
    errEl.textContent = String(err.message || err);
  }
}

$("imp-file-input").addEventListener("change", async (e) => {
  const f = e.target.files?.[0];
  e.target.value = "";
  if (!f) return;
  const prepared = await downscaleImageIfNeeded(f);
  await runFileExtractionFlow(prepared);
});

// 支持拖拽文件进入
const dz = $("imp-dropzone");
dz.addEventListener("dragover", (e) => {
  e.preventDefault();
  dz.classList.add("dragover");
});
dz.addEventListener("dragleave", () => dz.classList.remove("dragover"));
dz.addEventListener("drop", async (e) => {
  e.preventDefault();
  dz.classList.remove("dragover");
  const f = e.dataTransfer?.files?.[0];
  if (!f) return;
  const prepared = await downscaleImageIfNeeded(f);
  await runFileExtractionFlow(prepared);
});

// 支持在导密界面直接 Ctrl+V 粘贴剪贴板截图
document.addEventListener("paste", async (e) => {
  if ($("pane-importer").hidden) return;
  const items = Array.from(e.clipboardData?.items || []);
  const imgItem = items.find((it) => it.type.startsWith("image/"));
  if (!imgItem) return;
  e.preventDefault();
  const file = imgItem.getAsFile();
  if (!file) return;
  const prepared = await downscaleImageIfNeeded(new File([file], "剪贴板密码截图.png", { type: file.type }));
  await runFileExtractionFlow(prepared);
});

$("btn-imp-parse-text").addEventListener("click", async () => {
  const txt = $("imp-raw-text").value.trim();
  if (!txt) {
    showToast("请先输入或粘贴包含账号密码的文本");
    return;
  }
  await runFileExtractionFlow({
    name: "粘贴文本备忘.txt",
    mimeType: "text/plain",
    bytes: new TextEncoder().encode(txt),
  });
});

function renderPreviewTable() {
  const wrap = $("imp-preview-wrap");
  const tbody = $("imp-preview-tbody");
  tbody.textContent = "";
  wrap.hidden = state.previewItems.length === 0;
  if ($("imp-preview-summary")) {
    $("imp-preview-summary").textContent = `识别结果核对表（共 ${state.previewItems.length} 条，可直接点击单元格修改）`;
  }
  if (!state.previewItems.length) return;

  state.previewItems.forEach((row, idx) => {
    const tr = document.createElement("tr");

    const tdCheck = document.createElement("td");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.checked = row.selected !== false;
    cb.addEventListener("change", () => { row.selected = cb.checked; });
    tdCheck.appendChild(cb);

    const makeInputCell = (key) => {
      const td = document.createElement("td");
      const inp = document.createElement("input");
      inp.type = "text";
      inp.value = row[key] || "";
      inp.addEventListener("input", () => { row[key] = inp.value; });
      td.appendChild(inp);
      return td;
    };

    const tdUris = document.createElement("td");
    const uriInp = document.createElement("input");
    uriInp.type = "text";
    uriInp.value = (row.uris || []).join(", ");
    uriInp.addEventListener("input", () => {
      row.uris = uriInp.value.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
    });
    tdUris.appendChild(uriInp);

    const tdScope = document.createElement("td");
    const sel = document.createElement("select");
    for (const [val, label] of [
      ["universal", "🌐 三端通用"],
      ["web", "🕸 网页端"],
      ["desktop", "💻 电脑端"],
      ["mobile", "📱 手机端"],
    ]) {
      const opt = document.createElement("option");
      opt.value = val;
      opt.textContent = label;
      sel.appendChild(opt);
    }
    sel.value = row.pwdsvScope || "universal";
    sel.addEventListener("change", () => { row.pwdsvScope = sel.value; });
    tdScope.appendChild(sel);

    const tdState = document.createElement("td");
    const stSpan = document.createElement("span");
    stSpan.className = "badge";
    stSpan.textContent =
      row.duplicateAction === "update"
        ? "更新原密"
        : row.duplicateAction === "skip"
          ? "已存在"
          : "新建";
    tdState.appendChild(stSpan);

    tr.append(
      tdCheck,
      makeInputCell("name"),
      makeInputCell("username"),
      makeInputCell("password"),
      tdUris,
      tdScope,
      tdState,
    );
    tbody.appendChild(tr);
  });
}

$("imp-check-all").addEventListener("change", (e) => {
  const checked = e.target.checked;
  state.previewItems.forEach((r) => { r.selected = checked; });
  renderPreviewTable();
});

$("imp-batch-scope").addEventListener("change", (e) => {
  const target = e.target.value;
  if (!target) return;
  state.previewItems.forEach((r) => {
    if (r.selected !== false) r.pwdsvScope = target;
  });
  e.target.value = "";
  renderPreviewTable();
});

$("btn-imp-commit").addEventListener("click", async () => {
  const chosen = state.previewItems.filter((r) => r.selected !== false && (r.password || r.username));
  if (!chosen.length) {
    showToast("请至少勾选一条要上传的密码记录");
    return;
  }

  const btn = $("btn-imp-commit");
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = `正在本地加密并上传 ${chosen.length} 条记录…`;

  try {
    const token = await ensureAccessToken();
    const api = makeApiClient(state.session.serverUrl, state.session.insecureTls);

    // 区分新建条目（走 POST /api/ciphers/import 一次性批量导入）与更新已有条目（走 PUT /api/ciphers/<id>）
    const toCreate = [];
    const folderNameMap = new Map(state.folders.map((f) => [String(f.name || "").toLowerCase(), f.id]));
    const newFolders = [];
    const newFolderIndexByLower = new Map();
    const folderRelationships = [];
    let updatedCount = 0;

    for (const row of chosen) {
      if (row.duplicateAction === "update" && row.existingId) {
        const existingItem = state.items.find((i) => i.id === row.existingId);
        if (existingItem) {
          const payload = await buildLoginCipherPayload(
            {
              name: row.name,
              username: row.username,
              password: row.password,
              totp: row.totp || existingItem.totp || "",
              uris: row.uris?.length ? row.uris : existingItem.uris,
              notes: row.notes || existingItem.notes || "",
              folderId: existingItem.folderId,
              favorite: existingItem.favorite,
              pwdsvScope: row.pwdsvScope || "universal",
              pwdsvOriginDevice: "ai-import",
            },
            {
              userKey: state.session.userKey,
              userId: state.session.userId,
              keyId: state.session.keyId,
              existingItem,
            },
          );
          await api.updateCipher(token, existingItem.id, payload);
          updatedCount++;
          continue;
        }
      }

      let folderId = null;
      let newFolderIdx = -1;
      const fname = String(row.folderName || "").trim();
      if (fname) {
        const lower = fname.toLowerCase();
        if (folderNameMap.has(lower)) {
          folderId = folderNameMap.get(lower);
        } else if (newFolderIndexByLower.has(lower)) {
          newFolderIdx = newFolderIndexByLower.get(lower);
        } else {
          newFolderIdx = newFolders.length;
          newFolders.push({ name: await encryptText(state.session.userKey, fname) });
          newFolderIndexByLower.set(lower, newFolderIdx);
        }
      }

      const cipherIdx = toCreate.length;
      const payload = await buildLoginCipherPayload(
        {
          name: row.name,
          username: row.username,
          password: row.password,
          totp: row.totp || "",
          uris: row.uris || [],
          notes: row.notes || "",
          folderId,
          pwdsvScope: row.pwdsvScope || "universal",
          pwdsvOriginDevice: "ai-import",
        },
        {
          userKey: state.session.userKey,
          userId: state.session.userId,
          keyId: state.session.keyId,
        },
      );
      toCreate.push(payload);
      if (newFolderIdx >= 0) {
        folderRelationships.push({ key: cipherIdx, value: newFolderIdx });
      }
    }

    if (toCreate.length > 0) {
      await api.importCiphers(token, {
        ciphers: toCreate,
        folders: newFolders,
        folderRelationships,
      });
    }

    state.previewItems = [];
    $("imp-preview-wrap").hidden = true;
    await syncVault(true);
    showToast(`导入成功：新建 ${toCreate.length} 条，更新 ${updatedCount} 条！`);
  } catch (err) {
    $("imp-error").hidden = false;
    $("imp-error").textContent = "上传失败：" + String(err.message || err);
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
});

/* ---------------------------------------------------------------- 设置、一键更新与 PIN */

async function getDesktopAppVersion() {
  try {
    const v = await invoke("get_app_version");
    if (v) return String(v);
  } catch {
    /* 忽略 */
  }
  return "2.0.4";
}

function renderDesktopUpdateState(res = state.pendingUpdate, explicitMsg = "") {
  const statusEl = $("st-update-status");
  const applyBtn = $("btn-st-apply-update");
  const navBtn = $("btn-open-settings");
  const hasUpd = Boolean(res?.hasUpdate);
  if (navBtn) {
    navBtn.classList.toggle("has-update", hasUpd);
    navBtn.textContent = hasUpd ? "⚙ 设置 ●" : "⚙ 设置";
  }
  if (hasUpd) {
    if (statusEl) {
      statusEl.hidden = false;
      statusEl.textContent = `发现新版 v${res.latestVersion}${res.notes ? ` · ${res.notes}` : ""}`;
    }
    if (applyBtn) {
      applyBtn.hidden = false;
      applyBtn.textContent = `⬇ 一键更新至 v${res.latestVersion}`;
    }
  } else if (explicitMsg && statusEl) {
    statusEl.hidden = false;
    statusEl.textContent = explicitMsg;
    if (applyBtn) applyBtn.hidden = true;
  } else if (applyBtn) {
    applyBtn.hidden = true;
  }
}

async function checkDesktopUpdate(silent = false) {
  const curVer = await getDesktopAppVersion();
  if ($("st-cur-ver")) $("st-cur-ver").textContent = `v${curVer}`;
  const customUrl = ($("st-update-url")?.value ?? state.prefs.updateManifestUrl ?? "").trim();
  const statusEl = $("st-update-status");
  if (!silent && statusEl) {
    statusEl.hidden = false;
    statusEl.textContent = "正在拉取更新清单…";
  }
  try {
    const res = await checkClientUpdate({
      platform: "desktop",
      currentVersion: curVer,
      serverUrl: state.session?.serverUrl || state.prefs.serverUrl || "",
      customManifestUrl: customUrl,
      fetchImpl: makeTauriFetch(Boolean(state.session?.insecureTls ?? state.prefs.insecureTls)),
    });
    state.pendingUpdate = res.hasUpdate ? res : null;
    renderDesktopUpdateState(res, silent ? "" : `当前 v${curVer} 已是最新版本`);
    return res;
  } catch (err) {
    if (!silent) {
      renderDesktopUpdateState(null, "检查更新失败：" + String(err.message || err));
    }
    return null;
  }
}

async function openSettings() {
  await refreshPinStatus();
  const curVer = await getDesktopAppVersion();
  if ($("st-cur-ver")) $("st-cur-ver").textContent = `v${curVer}`;
  if ($("st-update-url")) $("st-update-url").value = state.prefs.updateManifestUrl || "";
  $("st-watch-enabled").checked = Boolean(state.prefs.watchEnabled);
  $("st-lock-mins").value = state.prefs.lockMinutes ?? 30;
  $("st-clip-sec").value = state.prefs.clipboardClearSeconds ?? 30;
  $("st-pin-status").textContent = state.hasPinConfigured
    ? "状态：已启用本地快捷 PIN（连续输错 5 次将自动销毁本地快捷凭据）"
    : "状态：尚未启用本地快捷 PIN";
  $("st-new-pin").value = "";
  renderDesktopUpdateState(state.pendingUpdate, "");
  showRightPane("settings");
}

$("btn-st-check-update")?.addEventListener("click", async () => {
  savePrefs({ updateManifestUrl: ($("st-update-url")?.value || "").trim() });
  const btn = $("btn-st-check-update");
  btn.disabled = true;
  try {
    await checkDesktopUpdate(false);
  } finally {
    btn.disabled = false;
  }
});

$("btn-st-apply-update")?.addEventListener("click", async () => {
  const upd = state.pendingUpdate;
  if (!upd?.downloadUrl) return;
  const btn = $("btn-st-apply-update");
  const statusEl = $("st-update-status");
  btn.disabled = true;
  if (statusEl) {
    statusEl.hidden = false;
    statusEl.textContent = "正在下载更新包并校验 SHA-256，校验通过后将自动替换重启…";
  }
  try {
    const msg = await invoke("download_and_install_update", {
      url: upd.downloadUrl,
      expectedSha256: upd.sha256 || "",
      insecureTls: Boolean(state.session?.insecureTls ?? state.prefs.insecureTls),
    });
    if (statusEl) statusEl.textContent = String(msg || "正在重启更新…");
  } catch (err) {
    if (statusEl) statusEl.textContent = "更新失败：" + String(err.message || err);
    showToast("更新失败：" + String(err.message || err));
    btn.disabled = false;
  }
});

$("btn-open-settings").addEventListener("click", openSettings);
$("btn-st-close").addEventListener("click", () => {
  if (state.selectedId) openDetail(state.selectedId);
  else showRightPane("welcome");
});

$("btn-st-save").addEventListener("click", async () => {
  savePrefs({
    watchEnabled: $("st-watch-enabled").checked,
    lockMinutes: Math.max(0, Math.min(1440, Number($("st-lock-mins").value) || 0)),
    clipboardClearSeconds: Math.max(5, Math.min(300, Number($("st-clip-sec").value) || 30)),
    updateManifestUrl: ($("st-update-url")?.value || "").trim(),
  });
  touchActivity();
  await pushWatchStateToRust();
  showToast("设置已保存");
});

$("btn-st-save-pin").addEventListener("click", async () => {
  const pin = $("st-new-pin").value.trim();
  if (pin.length < 4) {
    showToast("快捷 PIN 至少需要 4 位字符");
    return;
  }
  await savePinBlob(pin);
  $("st-new-pin").value = "";
  await openSettings();
  showToast("本地快捷 PIN 已更新");
});

$("btn-st-clear-pin").addEventListener("click", async () => {
  await invoke("clear_pin_vault");
  await refreshPinStatus();
  await openSettings();
  showToast("已关闭并清除本地快捷 PIN");
});

$("btn-sync-now").addEventListener("click", () => syncVault(false));
$("btn-lock-vault").addEventListener("click", () => lockVault("已手动锁定密码库"));

/* ------------------------------------------- 与后台应用监听钩子及悬浮 HUD 联动 */

listen("pwdsv://app-detected", async (event) => {
  const { hwnd, pid, exe, title, manualHotkey } = event.payload || {};
  if (!exe) return;

  if (!state.session) {
    if (manualHotkey) {
      await invoke("show_hud_with_payload", {
        payload: { hwnd, pid, exe, title, locked: true, candidates: [] },
      });
    }
    return;
  }

  const matched = state.items.filter((it) => {
    if (!isScopeApplicable(resolveItemScope(it), "desktop")) return false;
    if (!matchesApp(it, { exe, title })) return false;
    if (!manualHotkey && getTriggerRule(it) === "hotkey") return false;
    return true;
  });

  if (!matched.length && !manualHotkey) return;

  const candidates = [];
  for (const it of matched) {
    let totpCode = "";
    if (it.totp) {
      try {
        totpCode = (await generateTotp(it.totp)).code;
      } catch {
        totpCode = "";
      }
    }
    candidates.push({
      id: it.id,
      name: it.name || exe,
      username: it.username || "",
      totpCode,
    });
  }

  await invoke("show_hud_with_payload", {
    payload: { hwnd, pid, exe, title, locked: false, candidates },
  });
});

listen("pwdsv://hud-action", async (event) => {
  const act = event.payload || {};
  await invoke("hide_hud_window").catch(() => {});

  if (act.kind === "mute-pid") {
    if (act.pid) await invoke("mute_pid_session", { pid: act.pid });
    return;
  }

  if (act.kind === "add-for-app") {
    await invoke("focus_main_window");
    if (state.session) {
      await openEditor(null, { exe: act.exe, title: act.title });
    }
    return;
  }

  if (!state.session || !act.itemId) return;
  const item = state.items.find((i) => i.id === act.itemId);
  if (!item) return;

  if (act.kind === "autotype-pwd" || act.kind === "autotype-both") {
    await invoke("auto_type_secret", {
      hwnd: act.hwnd || 0,
      username: item.username || "",
      password: item.password || "",
      includeUsername: act.kind === "autotype-both",
    });
  } else if (act.kind === "copy-pwd") {
    await secureCopy(item.password, "密码");
  } else if (act.kind === "copy-totp" && item.totp) {
    const { code } = await generateTotp(item.totp);
    await secureCopy(code, "验证码");
  }
});

listen("pwdsv://tray-command", async (event) => {
  const cmd = event.payload?.command;
  if (cmd === "lock") {
    await lockVault("已通过托盘锁定密码库");
  } else if (cmd === "quick-add") {
    await invoke("focus_main_window");
    if (state.session) {
      await openEditor(null, event.payload?.app || null);
    }
  }
});

/* ------------------------------------------------------------------ 启动入口 */

(async function bootstrap() {
  await loadAiProvidersFromDisk();
  await refreshPinStatus();
  showUnlockForms(true);
})();
