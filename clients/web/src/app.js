/**
 * KeyNexus 浏览器网页端（直接挂载在服务端首页 `/`）
 * - 纯浏览器标准 Fetch + WebCrypto AES-256-CBC/HMAC-SHA256 零知识加解密
 * - 完整包含：四态工作台、Authenticator 独立动态码竖栏、AI 多格式导密、四端客户端下载中心
 */

import { PwdsvApi, ApiError, parseTwoFactorProviders, normalizeServerUrl } from "./lib/api.js";
import { deriveMasterKey, hashMasterPassword, makeRegisterPayload, SymmetricCryptoKey } from "./lib/crypto.js";
import { unlockUserKey, decryptSync, buildLoginCipherPayload } from "./lib/vault.js";
import { generateTotp, parseTotp } from "./lib/totp.js";
import { resolveItemScope, SCOPE_LABELS } from "./lib/matcher.js";
import { generatePassword, estimateStrength } from "./lib/generator.js";
import { RealtimeHub } from "./lib/realtime.js";
import { PRESET_PROVIDERS, parsePasswordFile, testProviderConnection, fetchProviderModels } from "./lib/importer/index.js";
import { compareSemver, fetchReleaseCatalog, checkClientUpdate } from "./lib/updater.js";

const WEB_APP_VERSION = "2.1.0";
const PREFS_KEY = "pwdsv_web_prefs_v1";
const SESSION_KEY = "keynexus_web_session_v1";
const PROVIDERS_KEY = "pwdsv_web_ai_providers_v1";
let lastPersistTouchAt = 0;

const VALID_THEMES = new Set(["system", "dark", "light"]);
const systemDarkMq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;

const SVG_ICONS = {
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>',
  moon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>',
  globe: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  web: '<rect x="3" y="4" width="18" height="16" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><circle cx="7" cy="6.5" r=".5"/><circle cx="10" cy="6.5" r=".5"/>',
  monitor: '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
  smartphone: '<rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/>',
  puzzle: '<path d="M19.439 7.85c-.049.322.059.648.289.878l1.568 1.568c.47.47.706 1.087.706 1.704s-.235 1.233-.706 1.704l-1.611 1.611a.98.98 0 0 1-.837.276c-.47-.07-.802-.48-.968-.925a2.501 2.501 0 1 0-3.214 3.214c.446.166.855.497.925.968a.979.979 0 0 1-.276.837l-1.61 1.61a2.404 2.404 0 0 1-1.705.707 2.402 2.402 0 0 1-1.704-.706l-1.568-1.568a1.026 1.026 0 0 0-.877-.29c-.493.074-.84.504-1.02.968a2.5 2.5 0 1 1-3.237-3.237c.464-.18.894-.527.967-1.02a1.026 1.026 0 0 0-.289-.877l-1.568-1.568A2.402 2.402 0 0 1 1.998 12c0-.617.236-1.234.706-1.704L4.23 8.77c.24-.24.581-.353.917-.303.515.077.877.528 1.073 1.01a2.5 2.5 0 1 0 3.259-3.259c-.482-.196-.933-.558-1.01-1.073-.05-.336.062-.676.303-.917l1.525-1.525A2.402 2.402 0 0 1 12 1.998c.617 0 1.234.236 1.704.706l1.568 1.568c.23.23.556.338.877.29.493-.074.84-.504 1.02-.968a2.5 2.5 0 1 1 3.237 3.237c-.464.18-.894.527-.967 1.02Z"/>',
  layers: '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
  clock: '<circle cx="12" cy="13" r="8"/><path d="M12 9v4l2 2"/><path d="M9 2h6"/>',
  star: '<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>',
  folder: '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
  refresh: '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
  arrowUpCircle: '<circle cx="12" cy="12" r="10"/><polyline points="16 12 12 8 8 12"/><line x1="12" y1="16" x2="12" y2="8"/>',
  arrowUp: '<line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/>',
  arrowDown: '<line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/>',
  x: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
  chevronRight: '<polyline points="9 18 15 12 9 6"/>',
  search: '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
  plus: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
  zap: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
  image: '<rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/>',
};

function svgIcon(name, className = "ic sm", { filled = false } = {}) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("class", filled ? `${className} filled` : className);
  svg.innerHTML = SVG_ICONS[name] || "";
  return svg;
}

function loadPrefs() {
  try {
    const raw = JSON.parse(localStorage.getItem(PREFS_KEY) || "{}");
    const hasKeepSignedIn = Object.prototype.hasOwnProperty.call(raw, "keepSignedIn");
    const migratedLock = !hasKeepSignedIn && (raw.lockMinutes === 30 || raw.lockMinutes == null) ? 0 : (raw.lockMinutes ?? 0);
    const prefs = {
      serverUrl: raw.serverUrl || window.location.origin,
      email: raw.email || "",
      deviceId: raw.deviceId || crypto.randomUUID(),
      keepSignedIn: hasKeepSignedIn ? Boolean(raw.keepSignedIn) : true,
      lockMinutes: migratedLock,
      clipboardClearSeconds: raw.clipboardClearSeconds ?? 30,
      updateManifestUrl: raw.updateManifestUrl || "",
      theme: VALID_THEMES.has(raw.theme) ? raw.theme : "dark",
    };
    localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
    return prefs;
  } catch {
    const prefs = {
      serverUrl: window.location.origin,
      email: "",
      deviceId: crypto.randomUUID(),
      keepSignedIn: true,
      lockMinutes: 0,
      clipboardClearSeconds: 30,
      updateManifestUrl: "",
      theme: "dark",
    };
    localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
    return prefs;
  }
}

function persistWebSession(session) {
  try {
    if (state.prefs.keepSignedIn === false || !session?.userKey) {
      localStorage.removeItem(SESSION_KEY);
      return;
    }
    localStorage.setItem(
      SESSION_KEY,
      JSON.stringify({
        userKeyB64: session.userKey.toB64(),
        userId: session.userId || "",
        keyId: session.keyId || null,
        email: session.email || "",
        serverUrl: session.serverUrl || "",
        accessToken: session.accessToken || "",
        refreshToken: session.refreshToken || "",
        tokenExpiresAt: session.tokenExpiresAt || 0,
        lastActiveAt: Date.now(),
      }),
    );
  } catch {
    // Ignore storage quota or private-mode failures.
  }
}

function clearPersistedWebSession() {
  try {
    localStorage.removeItem(SESSION_KEY);
  } catch {
    // Ignore storage cleanup failures.
  }
}

function savePrefs(patch) {
  state.prefs = { ...state.prefs, ...patch };
  localStorage.setItem(PREFS_KEY, JSON.stringify(state.prefs));
  return state.prefs;
}

const $ = (id) => document.getElementById(id);

const state = {
  prefs: loadPrefs(),
  session: null,
  items: [],
  folders: [],
  domains: null,
  filter: "all",
  selectedId: null,
  editingId: null,
  revealed: false,
  totpTimer: null,
  authPaneTimer: null,
  authCardRefs: [],
  idleTimer: null,
  providers: [],
  activeProviderId: "",
  activeModelId: "",
  activeVisionProviderId: "",
  activeVisionModelId: "",
  expandedProviderId: null,
  addProviderOpen: false,
  addProviderMode: "catalog",
  editorDraft: null,
  savedProviderNotice: "",
  pickerState: null,
  previewItems: [],
  releaseManifest: null,
};

function resolveTheme(themePref = state.prefs.theme) {
  if (themePref === "light") return "light";
  if (themePref === "dark") return "dark";
  return systemDarkMq?.matches ? "dark" : "light";
}

function updateThemeSwitcherButtons(resolved) {
  const nextIcon = resolved === "dark" ? "sun" : "moon";
  const nextLabel = resolved === "dark" ? "浅色" : "深色";
  const nextTitle = resolved === "dark" ? "切换到陶瓷浅色主题" : "切换到黑曜石深色主题";

  const authBtn = $("btn-auth-theme");
  if (authBtn) {
    authBtn.textContent = "";
    authBtn.title = nextTitle;
    authBtn.setAttribute("aria-label", nextTitle);
    const lbl = document.createElement("span");
    lbl.id = "auth-theme-label";
    lbl.textContent = nextLabel;
    authBtn.append(svgIcon(nextIcon, "ic sm"), lbl);
  }

  const sideBtn = $("btn-sidebar-theme");
  if (sideBtn) {
    sideBtn.textContent = "";
    sideBtn.title = nextTitle;
    sideBtn.setAttribute("aria-label", nextTitle);
    sideBtn.appendChild(svgIcon(nextIcon, "ic sm"));
  }
}

function applyTheme(themePref = state.prefs.theme) {
  const resolved = resolveTheme(themePref);
  document.documentElement.setAttribute("data-theme", resolved);
  updateThemeSwitcherButtons(resolved);
  return resolved;
}

function toggleQuickTheme() {
  const currentResolved = resolveTheme(state.prefs.theme);
  const next = currentResolved === "dark" ? "light" : "dark";
  savePrefs({ theme: next });
  applyTheme(next);
  if ($("st-theme")) $("st-theme").value = next;
}

applyTheme(state.prefs.theme);
systemDarkMq?.addEventListener?.("change", () => {
  if (state.prefs.theme === "system") applyTheme("system");
});
$("btn-auth-theme")?.addEventListener("click", toggleQuickTheme);
$("btn-sidebar-theme")?.addEventListener("click", toggleQuickTheme);

const realtimeHub = new RealtimeHub({
  onSyncNeeded: async () => {
    if (state.session) await syncVault(true);
  },
  onForceLogout: () => lockVault("收到服务端登出指令，已锁定"),
});

/* ----------------------------------------------------- 基础 UI 与安全辅助 */

let toastT = null;
function showToast(msg) {
  const bar = $("toast-bar");
  bar.textContent = msg;
  bar.hidden = false;
  if (toastT) clearTimeout(toastT);
  toastT = setTimeout(() => { bar.hidden = true; }, 3500);
}

function touchActivity() {
  if (!state.session) return;
  if (state.idleTimer) clearTimeout(state.idleTimer);
  const mins = Number(state.prefs.lockMinutes || 0);
  if (mins > 0) {
    state.idleTimer = setTimeout(() => lockVault("空闲超时，网页端已自动锁定"), mins * 60000);
    if (state.prefs.keepSignedIn !== false && Date.now() - lastPersistTouchAt > 30000) {
      lastPersistTouchAt = Date.now();
      persistWebSession(state.session);
    }
  }
}
["mousedown", "keydown"].forEach((ev) => document.addEventListener(ev, touchActivity, true));

function stopTotpTimer() {
  if (state.totpTimer) clearInterval(state.totpTimer);
  state.totpTimer = null;
}

function stopAuthPaneTimer() {
  if (state.authPaneTimer) clearInterval(state.authPaneTimer);
  state.authPaneTimer = null;
}

function showRightPane(which) {
  if (which !== "authenticator") stopAuthPaneTimer();
  if (which !== "detail") stopTotpTimer();
  for (const id of ["welcome", "detail", "authenticator", "editor", "importer", "providers", "downloads", "settings"]) {
    const el = $("pane-" + id);
    if (el) el.hidden = id !== which;
  }
}

async function copySensitive(text, label = "内容") {
  if (!text) return;
  await navigator.clipboard.writeText(text);
  const clearSec = Number(state.prefs.clipboardClearSeconds || 30);
  showToast(`${label}已复制（${clearSec}s 后自动清空剪贴板）`);
  if (clearSec > 0) {
    setTimeout(() => {
      navigator.clipboard.writeText("").catch(() => {});
    }, clearSec * 1000);
  }
}

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

function makeApiClient(serverUrl) {
  return new PwdsvApi(normalizeServerUrl(serverUrl || window.location.origin), {
    deviceId: state.prefs.deviceId,
    deviceName: "KeyNexus Web",
    deviceType: 9,
    clientName: "web",
  });
}

async function ensureAccessToken() {
  const s = state.session;
  if (!s) throw new Error("密码库已锁定");
  if (s.accessToken && Date.now() < (s.tokenExpiresAt || 0)) return s.accessToken;
  const api = makeApiClient(s.serverUrl);
  try {
    const t = await api.refresh(s.refreshToken);
    s.accessToken = t.accessToken;
    s.refreshToken = t.refreshToken;
    s.tokenExpiresAt = Date.now() + (t.expiresIn || 3600) * 1000 - 60000;
    persistWebSession(s);
    return s.accessToken;
  } catch (err) {
    if (err instanceof ApiError && (err.status === 400 || err.status === 401)) {
      lockVault("登录状态已过期，请重新登录");
    }
    throw err;
  }
}

function makeWebAiFetch() {
  async function callRelay(targetUrl, init = {}) {
    const token = await ensureAccessToken();
    const relayUrl = `${window.location.origin}/ai-relay`;
    const reqHeaders = {};
    if (init.headers) {
      if (init.headers instanceof Headers) {
        init.headers.forEach((v, k) => {
          reqHeaders[k] = v;
        });
      } else if (typeof init.headers === "object") {
        Object.assign(reqHeaders, init.headers);
      }
    }
    const res = await fetch(relayUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-KeyNexus-Auth": `Bearer ${token}`,
      },
      body: JSON.stringify({
        url: String(targetUrl || ""),
        method: String(init.method || "GET").toUpperCase(),
        headers: reqHeaders,
        body: init.body ?? null,
      }),
    });
    if (res.status === 404 && res.headers.get("X-KeyNexus-Relay") !== "1") {
      throw new Error("服务端尚未启用 /ai-relay 中继服务，请先在服务器更新 Caddy 与 compose 配置");
    }
    return {
      ok: res.ok,
      status: res.status,
      text: () => res.text(),
    };
  }

  return async function webAiFetch(url, init = {}) {
    const target = String(url || "");
    if (window.location?.protocol === "https:" && /^http:\/\//i.test(target) && state.session) {
      return await callRelay(target, init);
    }
    try {
      return await fetch(target, init);
    } catch (directErr) {
      if (state.session && /^https?:\/\//i.test(target)) {
        return await callRelay(target, init);
      }
      throw directErr;
    }
  };
}

/* ----------------------------------------------------- 四端客户端下载中心 */

function formatSize(bytes) {
  const n = Number(bytes || 0);
  if (!n) return "—";
  if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(2) + " MB";
  return Math.max(1, Math.round(n / 1024)) + " KB";
}

function absUrl(rel, serverUrl) {
  const raw = String(rel || "").trim();
  if (!raw) return "";
  if (/^https?:\/\//i.test(raw)) return raw;
  const base = normalizeServerUrl(serverUrl || state.session?.serverUrl || $("auth-server")?.value || window.location.origin);
  return new URL(raw, base + "/").toString();
}

async function fetchReleaseManifest(serverUrl = "") {
  const base = normalizeServerUrl(serverUrl || state.session?.serverUrl || $("auth-server")?.value || window.location.origin);
  const url = `${base}/client-releases/latest.json`;
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const data = await res.json();
  state.releaseManifest = data;
  return { data, base };
}

async function renderAuthDownloads() {
  const grid = $("auth-downloads-grid");
  const verEl = $("auth-dl-ver");
  if (!grid) return;
  try {
    const data = await fetchReleaseCatalog({
      serverUrl: window.location.origin,
      customManifestUrl: state.prefs.updateManifestUrl || "",
    });
    state.releaseManifest = data;
    if (verEl) {
      const srcTag = data.sourceType === "github" ? "GitHub Release" : "服务器";
      verEl.textContent = data.publishedAt ? `${srcTag} · ${data.publishedAt.slice(0, 10)}` : srcTag;
    }
    const defs = [
      { key: "desktop", icon: "monitor", title: "Windows 电脑端", ext: ".exe" },
      { key: "mobile", icon: "smartphone", title: "Android 手机端", ext: ".apk" },
      { key: "extension", icon: "puzzle", title: "Chrome / Edge 插件", ext: ".zip" },
    ];
    grid.textContent = "";
    for (const d of defs) {
      const entry = data[d.key];
      const a = document.createElement("a");
      a.className = "auth-dl-item";
      if (entry?.downloadUrl) {
        a.href = entry.downloadUrl;
        a.setAttribute("download", "");
      } else {
        a.href = "#";
      }
      const b = document.createElement("b");
      b.append(svgIcon(d.icon, "ic sm"), document.createTextNode(d.title));
      const sm = document.createElement("small");
      sm.textContent = entry?.version ? `v${entry.version} · ${formatSize(entry.size)} (${d.ext})` : "暂未挂载产物";
      a.append(b, sm);
      grid.appendChild(a);
    }
  } catch {
    if (verEl) verEl.textContent = "未检测到 /client-releases/latest.json";
  }
}

async function openDownloadsPane() {
  showRightPane("downloads");
  if ($("dl-update-source")) $("dl-update-source").value = state.prefs.updateManifestUrl || "";
  const cardsEl = $("dl-cards");
  const metaEl = $("dl-meta");
  const webBanner = $("dl-web-update-banner");
  if (webBanner) webBanner.hidden = true;
  cardsEl.textContent = "";
  metaEl.textContent = "正在拉取最新四端更新目录…";
  try {
    const data = await fetchReleaseCatalog({
      serverUrl: state.session?.serverUrl || state.prefs.serverUrl,
      customManifestUrl: ($("dl-update-source")?.value ?? state.prefs.updateManifestUrl ?? "").trim(),
    });
    state.releaseManifest = data;
    const srcLabel = data.sourceType === "github" ? "GitHub Releases" : "自托管服务器";
    metaEl.textContent = `来源：${srcLabel} · 发布时间：${data.publishedAt || "—"} · 说明：${data.notes || "四端统一分发"}`;

    const webVer = data.web?.version || data.version || "";
    if (webBanner && webVer && compareSemver(webVer, WEB_APP_VERSION) > 0) {
      webBanner.hidden = false;
      webBanner.textContent = "";
      webBanner.append(
        svgIcon("arrowUpCircle", "ic sm"),
        document.createTextNode(`检测到新版网页端 v${webVer}（当前运行 v${WEB_APP_VERSION}）：若从 GitHub 发版，请下载新版网页包更新服务端目录或刷新缓存。`),
      );
    }

    const specs = [
      { key: "web", icon: "globe", name: "Web 网页中枢（当前端）", desc: `当前运行 v${WEB_APP_VERSION}，可一键拉取新版网页静态包或直接刷新重载。` },
      { key: "desktop", icon: "monitor", name: "Windows 桌面守护端", desc: "支持 Win32 前台应用监听、无焦点悬浮 HUD、Simulate 输入与应用内一键更新。" },
      { key: "mobile", icon: "smartphone", name: "Android 手机端 APK", desc: "支持拍照 AI 识密、系统级密码自动填充、指纹解锁与应用内一键更新。" },
      { key: "extension", icon: "puzzle", name: "Chrome / Edge 浏览器扩展", desc: "支持网页自动填充/抓密、跨站搜索、右键菜单与更新提示。" },
    ];
    for (const s of specs) {
      const entry = data[s.key] || {};
      const card = document.createElement("div");
      card.className = "dl-card";
      const head = document.createElement("div");
      head.className = "dl-card-head";
      const b = document.createElement("b");
      b.append(svgIcon(s.icon, "ic sm"), document.createTextNode(s.name));
      const badge = document.createElement("span");
      badge.className = "badge universal";
      badge.textContent = entry.version ? `v${entry.version}` : s.key === "web" ? `v${WEB_APP_VERSION}` : "未挂载";
      head.append(b, badge);

      const p = document.createElement("p");
      p.className = "muted";
      p.style.margin = "0";
      p.textContent = s.desc;
      card.append(head, p);

      if (entry.sha256) {
        const sha = document.createElement("div");
        sha.className = "dl-sha";
        sha.textContent = `大小：${formatSize(entry.size)}  |  SHA-256：${entry.sha256}`;
        card.appendChild(sha);
      }

      const row = document.createElement("div");
      row.className = "inline-row";
      row.style.marginTop = "4px";
      if (s.key === "web") {
        const reloadBtn = document.createElement("button");
        reloadBtn.type = "button";
        reloadBtn.className = "ghost small";
        reloadBtn.append(svgIcon("refresh", "ic sm"), document.createTextNode("强制刷新网页"));
        reloadBtn.addEventListener("click", () => window.location.reload());
        row.appendChild(reloadBtn);
        if (entry.downloadUrl && entry.downloadUrl !== "/" && !entry.downloadUrl.endsWith("/releases/latest")) {
          const dlA = document.createElement("a");
          dlA.href = entry.downloadUrl;
          dlA.setAttribute("download", "");
          dlA.style.textDecoration = "none";
          const dlBtn = document.createElement("button");
          dlBtn.type = "button";
          dlBtn.className = "primary";
          dlBtn.append(svgIcon("download", "ic sm"), document.createTextNode(`下载新版网页包 (${formatSize(entry.size)})`));
          dlA.appendChild(dlBtn);
          row.appendChild(dlA);
        }
      } else if (entry.downloadUrl) {
        const dlBtn = document.createElement("a");
        dlBtn.href = entry.downloadUrl;
        dlBtn.setAttribute("download", "");
        dlBtn.style.textDecoration = "none";
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "primary";
        btn.append(svgIcon("download", "ic sm"), document.createTextNode(`下载安装包 (${formatSize(entry.size)})`));
        dlBtn.appendChild(btn);
        row.appendChild(dlBtn);
        if (entry.sha256) {
          const cp = document.createElement("button");
          cp.type = "button";
          cp.className = "ghost small";
          cp.textContent = "复制 SHA-256";
          cp.addEventListener("click", () => copySensitive(entry.sha256, "SHA-256 校验值"));
          row.appendChild(cp);
        }
      }
      card.appendChild(row);
      cardsEl.appendChild(card);
    }
  } catch (err) {
    metaEl.textContent = "加载清单失败：" + String(err.message || err);
  }
}

$("btn-dl-check")?.addEventListener("click", () => {
  savePrefs({ updateManifestUrl: ($("dl-update-source")?.value || "").trim() });
  openDownloadsPane();
});
$("dl-update-source")?.addEventListener("change", () => {
  savePrefs({ updateManifestUrl: $("dl-update-source").value.trim() });
});

$("btn-open-downloads").addEventListener("click", openDownloadsPane);
$("sc-go-dl")?.addEventListener("click", openDownloadsPane);
$("sc-go-auth")?.addEventListener("click", () => {
  state.filter = "totp";
  renderSidebarAndList();
  openAuthenticatorPane();
});
$("btn-dl-refresh")?.addEventListener("click", openDownloadsPane);

/* ----------------------------------------------------- 登录 / 注册 / 锁定 / 同步 */

function setAuthMode(mode = "login") {
  const isReg = mode === "register";
  $("tab-auth-login")?.classList.toggle("active", !isReg);
  $("tab-auth-register")?.classList.toggle("active", isReg);
  $("tab-auth-login")?.setAttribute("aria-selected", String(!isReg));
  $("tab-auth-register")?.setAttribute("aria-selected", String(isReg));
  if ($("unlock-form")) $("unlock-form").hidden = isReg;
  if ($("register-form")) $("register-form").hidden = !isReg;
  if (isReg && $("reg-server") && $("auth-server")?.value) {
    $("reg-server").value = $("auth-server").value;
  } else if (!isReg && $("auth-server") && $("reg-server")?.value) {
    $("auth-server").value = $("reg-server").value;
  }
  if ($("auth-error")) $("auth-error").hidden = true;
  if ($("reg-error")) $("reg-error").hidden = true;
  if ($("reg-ok")) $("reg-ok").hidden = true;
}

$("tab-auth-login")?.addEventListener("click", () => setAuthMode("login"));
$("tab-auth-register")?.addEventListener("click", () => setAuthMode("register"));

$("reg-password")?.addEventListener("input", () => {
  renderStrengthBadge($("reg-pwd-strength"), $("reg-password").value, "strength-pill");
});

$("register-form")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("btn-register");
  const errEl = $("reg-error");
  const okEl = $("reg-ok");
  errEl.hidden = true;
  okEl.hidden = true;

  const serverUrl = normalizeServerUrl($("reg-server").value);
  const email = $("reg-email").value.trim().toLowerCase();
  const name = $("reg-name").value.trim();
  const password = $("reg-password").value;
  const password2 = $("reg-password2").value;
  const masterPasswordHint = $("reg-hint").value.trim();

  if (password.length < 8) {
    errEl.hidden = false;
    errEl.textContent = "主密码长度至少 8 位";
    return;
  }
  if (password !== password2) {
    errEl.hidden = false;
    errEl.textContent = "两次输入的主密码不一致";
    return;
  }

  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = "正在本地派生零知识密钥并注册…";

  try {
    const payload = await makeRegisterPayload({
      email,
      password,
      name,
      masterPasswordHint,
    });
    const api = makeApiClient(serverUrl);
    await api.register(payload);

    $("auth-server").value = serverUrl;
    $("auth-email").value = email;
    $("auth-password").value = password;
    $("reg-password").value = "";
    $("reg-password2").value = "";
    renderStrengthBadge($("reg-pwd-strength"), "", "strength-pill");

    setAuthMode("login");
    okEl.hidden = false;
    okEl.textContent = "注册成功！正在自动登录进入工作台…";
    showToast("账号注册成功，正在自动登录…");
    $("unlock-form")?.requestSubmit();
  } catch (err) {
    errEl.hidden = false;
    errEl.textContent = String(err.message || err);
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
});

function showAuthView() {
  $("auth-screen").hidden = false;
  $("workspace").hidden = true;
  const defaultServer = state.prefs.serverUrl || window.location.origin;
  $("auth-server").value = defaultServer;
  if ($("reg-server")) $("reg-server").value = defaultServer;
  $("auth-email").value = state.prefs.email || "";
  if ($("auth-keep-signed-in")) $("auth-keep-signed-in").checked = state.prefs.keepSignedIn !== false;
  $("auth-error").hidden = true;
  setAuthMode("login");
  renderAuthDownloads();
}

$("auth-2fa-provider").addEventListener("change", () => {
  $("btn-auth-email-otp").hidden = Number($("auth-2fa-provider").value) !== 1;
});

$("btn-auth-email-otp").addEventListener("click", async () => {
  const btn = $("btn-auth-email-otp");
  btn.disabled = true;
  try {
    const api = makeApiClient($("auth-server").value);
    const email = $("auth-email").value.trim();
    const password = $("auth-password").value;
    const kdf = await api.prelogin(email);
    const mk = await deriveMasterKey(password, email, kdf);
    const hash = await hashMasterPassword(mk, password);
    await api.sendEmailLoginOtp({ email, masterPasswordHash: hash });
    showToast("已通知服务端发送邮件验证码");
  } catch (e) {
    $("auth-error").hidden = false;
    $("auth-error").textContent = String(e.message || e);
  } finally {
    btn.disabled = false;
  }
});

$("unlock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("btn-unlock");
  const errEl = $("auth-error");
  errEl.hidden = true;
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = "正在派生主密钥并同步…";

  try {
    const serverUrl = normalizeServerUrl($("auth-server").value);
    const email = $("auth-email").value.trim();
    const password = $("auth-password").value;
    const api = makeApiClient(serverUrl);
    const kdf = await api.prelogin(email);
    const masterKey = await deriveMasterKey(password, email, kdf);
    const masterPasswordHash = await hashMasterPassword(masterKey, password);

    const has2fa = !$("auth-2fa-box").hidden;
    let tokens;
    try {
      tokens = await api.login({
        email,
        masterPasswordHash,
        twoFactorToken: has2fa ? $("auth-2fa-code").value.trim() || undefined : undefined,
        twoFactorProvider: has2fa ? Number($("auth-2fa-provider").value || 0) : 0,
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
          $("auth-2fa-box").hidden = false;
          $("btn-auth-email-otp").hidden = Number(sel.value) !== 1;
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
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      tokenExpiresAt: Date.now() + (tokens.expiresIn || 3600) * 1000 - 60000,
    };
    state.items = vault.items;
    state.folders = vault.folders;
    state.domains = vault.domains;

    const keepSignedIn = $("auth-keep-signed-in") ? $("auth-keep-signed-in").checked : true;
    savePrefs({ serverUrl, email, keepSignedIn });
    persistWebSession(state.session);
    lastPersistTouchAt = Date.now();
    $("auth-password").value = "";
    $("auth-2fa-code").value = "";
    $("auth-2fa-box").hidden = true;

    $("auth-screen").hidden = true;
    $("workspace").hidden = false;
    $("sidebar-user-email").textContent = email;
    touchActivity();
    realtimeHub.connect(serverUrl, tokens.accessToken);
    renderSidebarAndList();
    showRightPane("welcome");
  } catch (err) {
    errEl.hidden = false;
    errEl.textContent = String(err.message || err);
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
});

function lockVault(reason = "网页端已锁定") {
  stopTotpTimer();
  stopAuthPaneTimer();
  if (state.idleTimer) clearTimeout(state.idleTimer);
  realtimeHub.disconnect();
  clearPersistedWebSession();
  state.session = null;
  state.items = [];
  state.selectedId = null;
  showAuthView();
  if (reason) showToast(reason);
}

async function syncVault(silent = false) {
  if (!state.session) return;
  try {
    const token = await ensureAccessToken();
    const api = makeApiClient(state.session.serverUrl);
    const data = await api.sync(token);
    const vault = await decryptSync(data, state.session.userKey);
    state.items = vault.items;
    state.folders = vault.folders;
    state.domains = vault.domains;
    renderSidebarAndList();
    if (state.selectedId && !$("pane-detail").hidden) {
      const still = state.items.find((i) => i.id === state.selectedId);
      if (still) openDetail(still.id);
    }
    if (!$("pane-authenticator").hidden) renderWebAuthCards();
    if (!silent) showToast(`同步完成，共 ${state.items.length} 条密码`);
  } catch (e) {
    if (!silent) showToast("同步失败：" + e.message);
  }
}

$("btn-sync-now").addEventListener("click", () => syncVault(false));
$("btn-lock-vault").addEventListener("click", () => lockVault("已锁定网页密码库"));

/* ----------------------------------------------------- 四态列表、详情与编辑器 */

function scopeBadgeClass(scope) {
  if (scope === "desktop") return "badge app";
  if (scope === "web") return "badge web";
  if (scope === "mobile") return "badge mobile";
  return "badge universal";
}
const SHORT_SCOPE_TEXT = { universal: "通用", desktop: "电脑", web: "网页", mobile: "手机" };
const FILTER_META = {
  all: { icon: "layers", label: "全部密码" },
  universal: { icon: "globe", label: "三端通用账户" },
  web: { icon: "web", label: "网页端专属" },
  desktop: { icon: "monitor", label: "电脑端专属" },
  mobile: { icon: "smartphone", label: "手机端专属" },
  fav: { icon: "star", label: "星标收藏" },
  totp: { icon: "clock", label: "Authenticator 验证器" },
};

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

function renderSidebarAndList() {
  const counts = { universal: 0, desktop: 0, web: 0, mobile: 0 };
  for (const it of state.items) {
    const sc = resolveItemScope(it);
    counts[sc] = (counts[sc] || 0) + 1;
  }
  $("cnt-all").textContent = String(state.items.length);
  $("cnt-universal").textContent = String(counts.universal);
  $("cnt-web").textContent = String(counts.web);
  $("cnt-desktop").textContent = String(counts.desktop);
  $("cnt-mobile").textContent = String(counts.mobile);
  $("cnt-fav").textContent = String(state.items.filter((i) => i.favorite).length);
  $("cnt-totp").textContent = String(state.items.filter((i) => Boolean(i.totp && String(i.totp).trim())).length);

  $("dash-cnt-uni").textContent = String(counts.universal);
  $("dash-cnt-web").textContent = String(counts.web);
  $("dash-cnt-desk").textContent = String(counts.desktop);
  $("dash-cnt-mob").textContent = String(counts.mobile);

  const fNav = $("folders-nav");
  fNav.textContent = "";
  for (const f of state.folders) {
    const btn = document.createElement("button");
    btn.type = "button";
    const key = "folder:" + f.id;
    btn.className = "nav-item" + (state.filter === key ? " active" : "");
    const lbl = document.createElement("span");
    lbl.className = "nav-lbl";
    const txt = document.createElement("span");
    txt.textContent = f.name || "未命名";
    lbl.append(svgIcon("folder", "ic sm"), txt);
    const em = document.createElement("em");
    em.textContent = String(state.items.filter((i) => i.folderId === f.id).length);
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
    if (state.filter === "totp") openAuthenticatorPane();
  });
});

document.querySelectorAll(".stat-tile[data-jump]").forEach((tile) => {
  tile.addEventListener("click", () => {
    state.filter = tile.dataset.jump || "all";
    renderSidebarAndList();
  });
});

function renderListOnly() {
  const list = filteredItems();
  const ul = $("vault-list");
  ul.textContent = "";
  $("vault-empty").hidden = list.length > 0;
  const titleEl = $("list-filter-title");
  titleEl.textContent = "";
  if (FILTER_META[state.filter]) {
    const meta = FILTER_META[state.filter];
    titleEl.append(svgIcon(meta.icon, "ic sm"), document.createTextNode(meta.label));
  } else if (state.filter.startsWith("folder:")) {
    const fname = state.folders.find((x) => x.id === state.filter.slice(7))?.name || "文件夹";
    titleEl.append(svgIcon("folder", "ic sm"), document.createTextNode(fname));
  } else {
    titleEl.append(svgIcon("layers", "ic sm"), document.createTextNode("全部密码"));
  }
  $("list-result-count").textContent = `${list.length} 项`;

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
    if (item.favorite) top.appendChild(svgIcon("star", "ic sm fav-star-ic", { filled: true }));
    const topTitle = document.createElement("span");
    topTitle.className = "row-top-title";
    topTitle.textContent = item.name || "(未命名)";
    top.appendChild(topTitle);
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
      const btnCopy = document.createElement("button");
      btnCopy.type = "button";
      btnCopy.className = "micro-btn";
      btnCopy.textContent = "复制密码";
      btnCopy.addEventListener("click", (ev) => {
        ev.stopPropagation();
        copySensitive(item.password, `「${item.name}」密码`);
      });
      quickOps.appendChild(btnCopy);
    }

    li.append(avatar, main, b, quickOps);
    ul.appendChild(li);
  }
}

$("vault-search").addEventListener("input", () => {
  renderListOnly();
  if (!$("pane-authenticator").hidden) renderWebAuthCards();
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
  const favBtn = $("btn-d-fav");
  favBtn.textContent = "";
  favBtn.appendChild(svgIcon("star", "ic", { filled: Boolean(item.favorite) }));
  favBtn.style.opacity = item.favorite ? "1" : "0.45";

  const badges = $("d-badges");
  badges.textContent = "";
  const sc = resolveItemScope(item);
  const scBadge = document.createElement("span");
  scBadge.className = scopeBadgeClass(sc);
  scBadge.textContent = SCOPE_LABELS[sc] || "三端通用";
  badges.appendChild(scBadge);
  if (item.pwdsvOriginDevice) {
    const o = document.createElement("span");
    o.className = "badge";
    o.textContent = `来源：${item.pwdsvOriginDevice}`;
    badges.appendChild(o);
  }

  $("d-username").textContent = item.username || "—";
  renderStrengthBadge($("d-strength-pill"), item.password);
  renderPasswordValue($("d-password"), item.password, false);

  $("d-uris-row").hidden = !item.uris?.length;
  $("d-uris").textContent = "";
  for (const u of item.uris || []) {
    const chip = document.createElement("div");
    chip.className = "uri-chip";
    chip.textContent = u.uri;
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
        const c = $("d-totp-circle");
        if (c) {
          c.setAttribute("stroke-dashoffset", (circumference * (1 - remaining / (period || 30))).toFixed(2));
          c.style.stroke = remaining <= 5 ? "var(--warn)" : "var(--totp)";
        }
      } catch {
        $("d-totp").textContent = "密钥无效";
        $("d-totp-left").textContent = "";
      }
    };
    tick();
    state.totpTimer = setInterval(tick, 1000);
  }
}

$("btn-d-fav").addEventListener("click", async () => {
  const item = state.items.find((i) => i.id === state.selectedId);
  if (!item || !state.session) return;
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
      pwdsvOriginDevice: item.pwdsvOriginDevice || "web",
    },
    { userKey: state.session.userKey, userId: state.session.userId, keyId: state.session.keyId, existingItem: item },
  );
  const api = makeApiClient(state.session.serverUrl);
  await api.updateCipher(await ensureAccessToken(), item.id, payload);
  await syncVault(true);
  showToast(nextFav ? "已加入星标收藏" : "已取消收藏");
});

$("btn-d-reveal").addEventListener("click", () => {
  const item = state.items.find((i) => i.id === state.selectedId);
  if (!item) return;
  state.revealed = !state.revealed;
  renderPasswordValue($("d-password"), item.password, state.revealed);
  $("btn-d-reveal").textContent = state.revealed ? "隐藏" : "显示";
});

document.querySelectorAll("[data-copy]").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const item = state.items.find((i) => i.id === state.selectedId);
    if (!item) return;
    const f = btn.dataset.copy;
    if (f === "username") await copySensitive(item.username, "账号");
    else if (f === "password") await copySensitive(item.password, "密码");
    else if (f === "totp" && item.totp) {
      const { code } = await generateTotp(item.totp);
      await copySensitive(code, "验证码");
    }
  });
});

$("btn-d-delete").addEventListener("click", async () => {
  const item = state.items.find((i) => i.id === state.selectedId);
  if (!item || !confirm(`确定永久删除「${item.name}」吗？`)) return;
  const api = makeApiClient(state.session.serverUrl);
  await api.deleteCipher(await ensureAccessToken(), item.id);
  state.selectedId = null;
  await syncVault(true);
  showRightPane("welcome");
  showToast("已删除该记录");
});

/* ----------------------------------------------------- 编辑器 & Authenticator 竖栏 */

function openEditor(item = null) {
  $("ed-error").hidden = true;
  $("f-password").type = "password";
  $("btn-f-eye").textContent = "显示";
  const sel = $("f-folder");
  sel.textContent = "";
  const none = document.createElement("option");
  none.value = "";
  none.textContent = "无文件夹";
  sel.appendChild(none);
  for (const f of state.folders) {
    const o = document.createElement("option");
    o.value = f.id;
    o.textContent = f.name || "未命名";
    sel.appendChild(o);
  }
  if (item) {
    state.editingId = item.id;
    $("ed-heading").textContent = `编辑：${item.name}`;
    $("f-name").value = item.name || "";
    $("f-scope").value = resolveItemScope(item);
    $("f-username").value = item.username || "";
    $("f-password").value = item.password || "";
    $("f-uris").value = (item.uris || []).map((u) => u.uri).join("\n");
    $("f-totp").value = item.totp || "";
    $("f-folder").value = item.folderId || "";
    $("f-favorite").checked = Boolean(item.favorite);
    $("f-notes").value = item.notes || "";
  } else {
    state.editingId = null;
    $("ed-heading").textContent = "提交新密码";
    $("f-name").value = "";
    $("f-scope").value = ["universal", "desktop", "web", "mobile"].includes(state.filter) ? state.filter : "universal";
    $("f-username").value = "";
    $("f-password").value = "";
    $("f-uris").value = "";
    $("f-totp").value = "";
    $("f-folder").value = "";
    $("f-favorite").checked = false;
    $("f-notes").value = "";
  }
  renderStrengthBadge($("f-pwd-strength"), $("f-password").value, "strength-inline");
  showRightPane("editor");
}

$("btn-new-item").addEventListener("click", () => openEditor(null));
$("btn-empty-create").addEventListener("click", () => openEditor(null));
$("btn-d-edit").addEventListener("click", () => {
  const item = state.items.find((i) => i.id === state.selectedId);
  if (item) openEditor(item);
});
$("btn-ed-cancel").addEventListener("click", () => (state.selectedId ? openDetail(state.selectedId) : showRightPane("welcome")));
$("f-password").addEventListener("input", () => renderStrengthBadge($("f-pwd-strength"), $("f-password").value, "strength-inline"));
$("btn-f-eye").addEventListener("click", () => {
  const h = $("f-password").type === "password";
  $("f-password").type = h ? "text" : "password";
  $("btn-f-eye").textContent = h ? "隐藏" : "显示";
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
    if (!$("f-password").value && !$("f-totp").value.trim()) throw new Error("密码和 Authenticator 密钥不能同时为空");
    const existingItem = state.editingId ? state.items.find((i) => i.id === state.editingId) : null;
    const uris = $("f-uris").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean).map((uri) => ({ uri, match: null }));
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
        pwdsvScope: $("f-scope").value || "universal",
        pwdsvOriginDevice: "web",
      },
      { userKey: state.session.userKey, userId: state.session.userId, keyId: state.session.keyId, existingItem },
    );
    const api = makeApiClient(state.session.serverUrl);
    const token = await ensureAccessToken();
    const saved = existingItem ? await api.updateCipher(token, existingItem.id, payload) : await api.createCipher(token, payload);
    await syncVault(true);
    openDetail(saved?.id || existingItem?.id);
    showToast("已本地零知识加密并同步至服务器");
  } catch (err) {
    errEl.hidden = false;
    errEl.textContent = String(err.message || err);
  } finally {
    btn.disabled = false;
  }
});

async function refreshWebAuthCodes() {
  const circumference = 131.95;
  await Promise.all(
    state.authCardRefs.map(async (ref) => {
      try {
        const { code, remaining, period } = await generateTotp(ref.totp);
        ref.currentCode = code;
        ref.codeEl.textContent = formatTotpSpaced(code);
        ref.leftEl.textContent = `${remaining}`;
        ref.leftEl.classList.toggle("urgent", remaining <= 5);
        ref.circleEl.setAttribute("stroke-dashoffset", (circumference * (1 - remaining / (period || 30))).toFixed(2));
        ref.circleEl.style.stroke = remaining <= 5 ? "var(--warn)" : "var(--totp)";
      } catch {
        ref.currentCode = "";
        ref.codeEl.textContent = "密钥无效";
        ref.leftEl.textContent = "";
      }
    }),
  );
}

function renderWebAuthCards() {
  const q = ($("vault-search")?.value || "").trim().toLowerCase();
  let list = state.items.filter((it) => Boolean(it.totp && String(it.totp).trim()));
  if (q) list = list.filter((it) => [it.name, it.username, it.notes].join(" ").toLowerCase().includes(q));
  list.sort((a, b) => (a.favorite === b.favorite ? String(a.name || "").localeCompare(String(b.name || ""), "zh-CN") : a.favorite ? -1 : 1));

  const container = $("da-list");
  container.textContent = "";
  state.authCardRefs = [];
  $("da-empty").hidden = list.length > 0;

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
    ringAvatar.innerHTML = `<svg class="da-ring-svg" viewBox="0 0 48 48" width="48" height="48"><circle class="ring-bg" cx="24" cy="24" r="21"/><circle class="ring-fg" cx="24" cy="24" r="21" stroke-dasharray="131.95" stroke-dashoffset="0"/></svg>`;
    const avatar = document.createElement("div");
    avatar.className = "squircle-avatar round";
    applyAvatarVisual(avatar, item.name || item.username, item.id);
    const leftEl = document.createElement("em");
    leftEl.className = "da-sec-badge";
    leftEl.textContent = "--";
    ringAvatar.append(avatar, leftEl);

    const meta = document.createElement("div");
    meta.className = "da-card-meta";
    const tl = document.createElement("div");
    tl.className = "da-title-line";
    const nm = document.createElement("span");
    nm.className = "da-card-name";
    if (item.favorite) nm.appendChild(svgIcon("star", "ic sm fav-star-ic", { filled: true }));
    nm.appendChild(document.createTextNode(item.name || "(未命名)"));
    const usr = document.createElement("span");
    usr.className = "da-card-user";
    usr.textContent = item.username || item.uris?.[0]?.uri || "验证器";
    tl.append(nm, usr);
    const codeEl = document.createElement("code");
    codeEl.className = "da-code";
    codeEl.textContent = "••• •••";
    meta.append(tl, codeEl);
    left.append(ringAvatar, meta);

    const ops = document.createElement("div");
    ops.className = "da-card-ops";
    const btnCopy = document.createElement("button");
    btnCopy.type = "button";
    btnCopy.className = "ghost small";
    btnCopy.textContent = "复制";
    const btnDetail = document.createElement("button");
    btnDetail.type = "button";
    btnDetail.className = "ghost small";
    btnDetail.title = "查看详情";
    btnDetail.setAttribute("aria-label", "查看详情");
    btnDetail.appendChild(svgIcon("chevronRight", "ic sm"));
    const ref = { id: item.id, name: item.name || "Authenticator", totp: item.totp, currentCode: "", codeEl, circleEl: ringAvatar.querySelector(".ring-fg"), leftEl };
    btnCopy.addEventListener("click", async () => {
      const code = ref.currentCode || (await generateTotp(item.totp)).code;
      await copySensitive(code, `「${ref.name}」验证码`);
    });
    btnDetail.addEventListener("click", () => openDetail(item.id));
    ops.append(btnCopy, btnDetail);

    card.append(accent, left, ops);
    container.appendChild(card);
    state.authCardRefs.push(ref);
  }
  refreshWebAuthCodes();
}

function openAuthenticatorPane() {
  stopTotpTimer();
  stopAuthPaneTimer();
  showRightPane("authenticator");
  renderWebAuthCards();
  state.authPaneTimer = setInterval(refreshWebAuthCodes, 1000);
}

$("btn-da-toggle-add").addEventListener("click", () => { $("da-add-form").hidden = !$("da-add-form").hidden; });
$("btn-da-cancel").addEventListener("click", () => { $("da-add-form").hidden = true; });
$("btn-da-empty-add").addEventListener("click", () => { $("da-add-form").hidden = false; });
$("da-secret").addEventListener("input", () => {
  const raw = $("da-secret").value.trim();
  if (!/^otpauth:\/\//i.test(raw)) return;
  try {
    const p = parseTotp(raw);
    if (p.issuer && !$("da-name").value.trim()) $("da-name").value = p.issuer;
    if (p.account && !$("da-user").value.trim()) $("da-user").value = p.account;
  } catch {}
});
$("da-add-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("btn-da-save");
  const errEl = $("da-add-err");
  errEl.hidden = true;
  btn.disabled = true;
  try {
    const secret = $("da-secret").value.trim();
    const name = $("da-name").value.trim();
    const username = $("da-user").value.trim();
    await generateTotp(secret);
    const payload = await buildLoginCipherPayload(
      { name, username, password: "", uris: [], totp: secret, favorite: false, notes: "", pwdsvScope: "universal", pwdsvOriginDevice: "web" },
      { userKey: state.session.userKey, userId: state.session.userId, keyId: state.session.keyId },
    );
    const api = makeApiClient(state.session.serverUrl);
    await api.createCipher(await ensureAccessToken(), payload);
    $("da-add-form").reset();
    $("da-add-form").hidden = true;
    await syncVault(true);
    renderWebAuthCards();
    showToast("Authenticator 验证器已加密保存");
  } catch (err) {
    errEl.hidden = false;
    errEl.textContent = String(err.message || err);
  } finally {
    btn.disabled = false;
  }
});

/* ----------------------------------------------------- AI 导入与模型提供商 + 设置 */

const PROTOCOL_LABELS = {
  "openai-compatible": "OpenAI 兼容",
  anthropic: "Anthropic Messages",
  gemini: "Google Gemini",
};

const BASE_URL_HINTS = {
  "openai-compatible": "https://api.openai.com/v1 或 http://152.32.234.200:8788/",
  anthropic: "https://api.anthropic.com 或 http://152.32.234.200:8788/",
  gemini: "https://generativelanguage.googleapis.com/v1beta",
};

function protocolLabel(protocol) {
  return PROTOCOL_LABELS[protocol] || protocol || "OpenAI 兼容";
}

function normalizeModelRow(row) {
  const id = String(row?.id || "").trim();
  const name = String(row?.name || "").trim();
  const rawMod = Array.isArray(row?.inputModalities)
    ? row.inputModalities
    : Array.isArray(row?.input)
      ? row.input
      : null;
  const mods = rawMod
    ? Array.from(new Set(rawMod.map((x) => String(x || "").toLowerCase()).filter((x) => x === "text" || x === "image")))
    : [];
  return {
    id,
    name: name && name !== id ? name : "",
    inputModalities: mods.length ? mods : ["text"],
  };
}

function normalizeWebProvider(raw) {
  const modelsMap = new Map();
  if (Array.isArray(raw?.models)) {
    for (const m of raw.models) {
      const nm = normalizeModelRow(m);
      if (nm.id && !modelsMap.has(nm.id)) modelsMap.set(nm.id, nm);
    }
  }
  if (!modelsMap.size) {
    const textId = String(raw?.textModel || "").trim();
    const visionId = String(raw?.visionModel || "").trim();
    if (textId) {
      modelsMap.set(textId, {
        id: textId,
        name: "",
        inputModalities: visionId && visionId === textId ? ["text", "image"] : ["text"],
      });
    }
    if (visionId && visionId !== textId) {
      modelsMap.set(visionId, { id: visionId, name: "", inputModalities: ["text", "image"] });
    }
  }
  const models = Array.from(modelsMap.values());
  const firstText = models[0]?.id || String(raw?.textModel || "").trim();
  const firstVision = models.find((m) => m.inputModalities.includes("image"))?.id || String(raw?.visionModel || "").trim();
  return {
    id: raw?.id || "web-" + Date.now(),
    name: String(raw?.name || "自定义网关").trim(),
    protocol: raw?.protocol || "openai-compatible",
    baseUrl: String(raw?.baseUrl || "").trim(),
    exactEndpoint: Boolean(raw?.exactEndpoint),
    apiKey: String(raw?.apiKey || "").trim(),
    customHeaders: String(raw?.customHeaders || "").trim(),
    requiresKey: raw?.requiresKey !== false,
    models,
    textModel: firstText,
    visionModel: firstVision,
  };
}

function ensureActiveModelValid() {
  let prov = state.providers.find((p) => p.id === state.activeProviderId) || state.providers[0];
  if (prov) {
    state.activeProviderId = prov.id;
    const hasText = prov.models?.some((m) => m.id === state.activeModelId);
    if (!hasText) state.activeModelId = prov.models?.[0]?.id || prov.textModel || "";
  } else {
    state.activeProviderId = "";
    state.activeModelId = "";
  }
  if (state.activeVisionProviderId && state.activeVisionModelId) {
    const vp = state.providers.find((p) => p.id === state.activeVisionProviderId);
    const hasVis = vp?.models?.some((m) => m.id === state.activeVisionModelId && m.inputModalities?.includes("image"));
    if (!hasVis) {
      state.activeVisionProviderId = "";
      state.activeVisionModelId = "";
    }
  }
}

function loadProviders() {
  try {
    const raw = JSON.parse(localStorage.getItem(PROVIDERS_KEY) || "null");
    if (raw?.providers?.length) {
      state.providers = raw.providers.map(normalizeWebProvider);
      state.activeProviderId = raw.activeProviderId || state.providers[0].id;
      state.activeModelId = raw.activeModelId || "";
      state.activeVisionProviderId = raw.activeVisionProviderId || "";
      state.activeVisionModelId = raw.activeVisionModelId || "";
      ensureActiveModelValid();
      return;
    }
  } catch {}
  state.providers = [
    normalizeWebProvider({ ...PRESET_PROVIDERS[0], id: "web-deepseek", apiKey: "", customHeaders: "" }),
    normalizeWebProvider({ ...PRESET_PROVIDERS[1], id: "web-qwen", apiKey: "", customHeaders: "" }),
    normalizeWebProvider({ ...PRESET_PROVIDERS[2], id: "web-gemini", apiKey: "", customHeaders: "" }),
  ];
  state.activeProviderId = state.providers[0].id;
  state.activeModelId = state.providers[0].models[0]?.id || "";
  state.activeVisionProviderId = "";
  state.activeVisionModelId = "";
}

function saveProviders() {
  ensureActiveModelValid();
  localStorage.setItem(
    PROVIDERS_KEY,
    JSON.stringify({
      activeProviderId: state.activeProviderId,
      activeModelId: state.activeModelId,
      activeVisionProviderId: state.activeVisionProviderId,
      activeVisionModelId: state.activeVisionModelId,
      providers: state.providers,
    }),
  );
}

function resolveEffectiveAiSelection() {
  ensureActiveModelValid();
  const baseProv = state.providers.find((p) => p.id === state.activeProviderId) || state.providers[0];
  const chosenModel = baseProv?.models?.find((m) => m.id === state.activeModelId) || baseProv?.models?.[0];

  let visionProv = null;
  let visionModelLabel = "";
  if (state.activeVisionProviderId && state.activeVisionModelId) {
    const vp = state.providers.find((p) => p.id === state.activeVisionProviderId);
    if (vp) {
      visionProv = { ...vp, textModel: state.activeVisionModelId, visionModel: state.activeVisionModelId };
      visionModelLabel = `${vp.name} / ${state.activeVisionModelId}`;
    }
  }
  if (!visionProv && baseProv) {
    const fallbackVid = chosenModel?.inputModalities?.includes("image")
      ? chosenModel.id
      : baseProv.models?.find((m) => m.inputModalities?.includes("image"))?.id || baseProv.visionModel || "";
    if (fallbackVid) {
      visionProv = { ...baseProv, visionModel: fallbackVid };
      visionModelLabel = `${baseProv.name} / ${fallbackVid}`;
    }
  }
  const effectiveProv = baseProv
    ? {
        ...baseProv,
        textModel: chosenModel?.id || baseProv.textModel,
        visionModel: visionProv?.visionModel || baseProv.visionModel,
      }
    : null;
  return { effectiveProv, visionProv, chosenModelId: effectiveProv?.textModel || "", visionModelLabel };
}

function providerHasCredential(p) {
  if (!p) return false;
  if (String(p.apiKey || "").trim()) return true;
  if (p.requiresKey === false) return true;
  return /localhost|127\.0\.0\.1|:11434/i.test(p.baseUrl || "");
}

function renderActiveModelSelectors() {
  ensureActiveModelValid();
  const textSel = $("active-text-model-select");
  const visionSel = $("active-vision-model-select");
  const badgeEl = $("prov-active-badge");

  if (textSel) {
    textSel.textContent = "";
    const targetVal = `${state.activeProviderId}::${state.activeModelId}`;
    for (const p of state.providers) {
      const grp = document.createElement("optgroup");
      grp.label = `${p.name} · ${protocolLabel(p.protocol)}`;
      const list = p.models?.length ? p.models : [{ id: p.textModel || p.visionModel || "", name: "", inputModalities: ["text"] }];
      for (const m of list) {
        if (!m.id) continue;
        const o = document.createElement("option");
        o.value = `${p.id}::${m.id}`;
        const labelBase = m.name && m.name !== m.id ? `${m.name} (${m.id})` : m.id;
        o.textContent = labelBase + (m.inputModalities?.includes("image") ? " · 文本+视觉" : "");
        grp.appendChild(o);
      }
      if (grp.children.length) textSel.appendChild(grp);
    }
    textSel.value = targetVal;
  }

  if (visionSel) {
    visionSel.textContent = "";
    const autoOpt = document.createElement("option");
    autoOpt.value = "";
    autoOpt.textContent = "自动跟随当前提供商的首个视觉模型";
    visionSel.appendChild(autoOpt);
    for (const p of state.providers) {
      const grp = document.createElement("optgroup");
      grp.label = `${p.name} · ${protocolLabel(p.protocol)}`;
      for (const m of p.models || []) {
        if (!m.id || !m.inputModalities?.includes("image")) continue;
        const o = document.createElement("option");
        o.value = `${p.id}::${m.id}`;
        o.textContent = m.name && m.name !== m.id ? `${m.name} (${m.id})` : m.id;
        grp.appendChild(o);
      }
      if (grp.children.length) visionSel.appendChild(grp);
    }
    const visVal = state.activeVisionProviderId && state.activeVisionModelId
      ? `${state.activeVisionProviderId}::${state.activeVisionModelId}`
      : "";
    visionSel.value = visVal;
  }

  if (badgeEl) {
    const { effectiveProv, chosenModelId, visionModelLabel } = resolveEffectiveAiSelection();
    if (effectiveProv && chosenModelId) {
      badgeEl.textContent = `文本：${effectiveProv.name} / ${chosenModelId}` + (visionModelLabel ? ` ｜ 视觉：${visionModelLabel}` : "");
    } else {
      badgeEl.textContent = "未选择具体模型";
    }
  }
}

$("active-text-model-select")?.addEventListener("change", () => {
  const raw = $("active-text-model-select").value || "";
  const sep = raw.indexOf("::");
  if (sep > 0) {
    state.activeProviderId = raw.slice(0, sep);
    state.activeModelId = raw.slice(sep + 2);
    saveProviders();
    renderProvidersPane();
    renderImpProviderSelect();
    showToast(`已切换当前文本模型：${state.activeModelId}`);
  }
});

$("active-vision-model-select")?.addEventListener("change", () => {
  const raw = $("active-vision-model-select").value || "";
  const sep = raw.indexOf("::");
  if (sep > 0) {
    state.activeVisionProviderId = raw.slice(0, sep);
    state.activeVisionModelId = raw.slice(sep + 2);
    showToast(`已固定视觉识图模型：${state.activeVisionModelId}`);
  } else {
    state.activeVisionProviderId = "";
    state.activeVisionModelId = "";
    showToast("视觉识图模型已设为自动跟随");
  }
  saveProviders();
  renderProvidersPane();
  renderImpProviderSelect();
});

function renderImpProviderSelect() {
  ensureActiveModelValid();
  const sel = $("imp-provider-select");
  if (!sel) return;
  sel.textContent = "";
  const targetVal = state.activeModelId ? `${state.activeProviderId}::${state.activeModelId}` : "";

  for (const p of state.providers) {
    const grp = document.createElement("optgroup");
    grp.label = `${p.name} · ${protocolLabel(p.protocol)}`;
    const list = p.models?.length ? p.models : [{ id: p.textModel || p.visionModel || "", name: "", inputModalities: ["text"] }];
    for (const m of list) {
      if (!m.id) continue;
      const val = `${p.id}::${m.id}`;
      const o = document.createElement("option");
      o.value = val;
      const labelBase = m.name && m.name !== m.id ? `${m.name} (${m.id})` : m.id;
      o.textContent = labelBase + (m.inputModalities?.includes("image") ? " · 文本+视觉" : "");
      grp.appendChild(o);
    }
    if (grp.children.length) sel.appendChild(grp);
  }
  if (targetVal) sel.value = targetVal;
  const hintEl = $("imp-active-model-hint");
  if (hintEl) {
    const { effectiveProv, chosenModelId, visionModelLabel } = resolveEffectiveAiSelection();
    hintEl.textContent = effectiveProv && chosenModelId
      ? `当前将使用 — 文本解析：${effectiveProv.name} / ${chosenModelId}` + (visionModelLabel ? ` ｜ 截图识图：${visionModelLabel}` : "（暂未配置视觉模型）")
      : "";
  }
}

$("btn-open-importer").addEventListener("click", () => { renderImpProviderSelect(); showRightPane("importer"); });
$("btn-empty-ai").addEventListener("click", () => { renderImpProviderSelect(); showRightPane("importer"); });
$("imp-provider-select").addEventListener("change", () => {
  const raw = $("imp-provider-select").value || "";
  const sep = raw.indexOf("::");
  if (sep > 0) {
    state.activeProviderId = raw.slice(0, sep);
    state.activeModelId = raw.slice(sep + 2);
  } else {
    state.activeProviderId = raw;
    state.activeModelId = "";
  }
  saveProviders();
  renderImpProviderSelect();
});
$("btn-imp-pick-file").addEventListener("click", () => $("imp-file-input").click());
$("btn-imp-toggle-text").addEventListener("click", () => { $("imp-raw-text-box").hidden = !$("imp-raw-text-box").hidden; });

async function runImport(fileObj) {
  $("imp-error").hidden = true;
  $("imp-status").hidden = false;
  try {
    const { effectiveProv, visionProv } = resolveEffectiveAiSelection();
    const res = await parsePasswordFile(fileObj, {
      provider: effectiveProv,
      visionProvider: visionProv || undefined,
      existingVaultItems: state.items,
      forceAi: $("imp-force-ai").checked,
      fetchImpl: makeWebAiFetch(),
      onProgress: (t) => { $("imp-status").textContent = t; },
    });
    state.previewItems = res.items || [];
    $("imp-status").textContent = `✓ 从「${res.fileName}」提取出 ${state.previewItems.length} 条记录`;
    renderPreviewTable();
  } catch (err) {
    $("imp-status").hidden = true;
    $("imp-error").hidden = false;
    $("imp-error").textContent = String(err.message || err);
  }
}

$("imp-file-input").addEventListener("change", async (e) => {
  const f = e.target.files?.[0];
  e.target.value = "";
  if (f) await runImport({ name: f.name, mimeType: f.type, bytes: new Uint8Array(await f.arrayBuffer()) });
});
$("btn-imp-parse-text").addEventListener("click", async () => {
  const txt = $("imp-raw-text").value.trim();
  if (txt) await runImport({ name: "粘贴文本.txt", mimeType: "text/plain", bytes: new TextEncoder().encode(txt) });
});
$("imp-dropzone").addEventListener("dragover", (e) => { e.preventDefault(); $("imp-dropzone").classList.add("dragover"); });
$("imp-dropzone").addEventListener("dragleave", () => $("imp-dropzone").classList.remove("dragover"));
$("imp-dropzone").addEventListener("drop", async (e) => {
  e.preventDefault();
  $("imp-dropzone").classList.remove("dragover");
  const f = e.dataTransfer?.files?.[0];
  if (f) await runImport({ name: f.name, mimeType: f.type, bytes: new Uint8Array(await f.arrayBuffer()) });
});

function renderPreviewTable() {
  const tbody = $("imp-preview-tbody");
  tbody.textContent = "";
  $("imp-preview-wrap").hidden = !state.previewItems.length;
  for (const row of state.previewItems) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td><input type="checkbox" ${row.selected !== false ? "checked" : ""}/></td><td></td><td></td><td></td><td></td><td></td><td>${row.duplicateAction === "update" ? "更新" : "新建"}</td>`;
    tr.cells[1].textContent = row.name || "";
    tr.cells[2].textContent = row.username || "";
    tr.cells[3].textContent = row.password ? "••••••" : "";
    tr.cells[4].textContent = (row.uris || []).map((u) => u.uri).join(", ");
    tr.cells[5].textContent = SCOPE_LABELS[row.pwdsvScope || "universal"] || "三端通用";
    tr.querySelector("input").addEventListener("change", (ev) => { row.selected = ev.target.checked; });
    tbody.appendChild(tr);
  }
}

$("imp-batch-scope").addEventListener("change", (e) => {
  if (!e.target.value) return;
  state.previewItems.forEach((r) => { if (r.selected !== false) r.pwdsvScope = e.target.value; });
  e.target.value = "";
  renderPreviewTable();
});

$("btn-imp-commit").addEventListener("click", async () => {
  const chosen = state.previewItems.filter((r) => r.selected !== false && (r.password || r.username));
  if (!chosen.length) return showToast("请至少选择一条记录");
  const api = makeApiClient(state.session.serverUrl);
  const token = await ensureAccessToken();
  const toCreate = [];
  for (const row of chosen) {
    toCreate.push(
      await buildLoginCipherPayload(
        { name: row.name, username: row.username, password: row.password, uris: row.uris || [], notes: row.notes || "", pwdsvScope: row.pwdsvScope || "universal", pwdsvOriginDevice: "web-ai" },
        { userKey: state.session.userKey, userId: state.session.userId, keyId: state.session.keyId },
      ),
    );
  }
  await api.importCiphers(token, { ciphers: toCreate, folders: [], folderRelationships: [] });
  state.previewItems = [];
  $("imp-preview-wrap").hidden = true;
  await syncVault(true);
  showToast(`已成功导入 ${toCreate.length} 条密码`);
});

function createDraftFromProvider(p) {
  const norm = normalizeWebProvider(p);
  const currentActive = state.activeProviderId === norm.id && norm.models.some((m) => m.id === state.activeModelId)
    ? state.activeModelId
    : norm.models[0]?.id || "";
  return {
    isNew: false,
    mode: "custom",
    id: norm.id,
    presetId: "",
    name: norm.name,
    protocol: norm.protocol,
    baseUrl: norm.baseUrl,
    exactEndpoint: norm.exactEndpoint,
    apiKey: norm.apiKey,
    customHeaders: norm.customHeaders,
    requiresKey: norm.requiresKey,
    selectedModelId: currentActive,
    models: norm.models.map((m) => ({ ...m, inputModalities: [...m.inputModalities] })),
    showKey: false,
    statusText: "",
    statusType: "",
    fetchMsg: "",
    fetchMsgType: "",
    fetching: false,
    testing: false,
  };
}

function createDraftForAdd(mode = "catalog", presetTpl = PRESET_PROVIDERS[0]) {
  if (mode === "catalog" && presetTpl) {
    const norm = normalizeWebProvider({ ...presetTpl, id: "web-" + presetTpl.id + "-" + Date.now(), apiKey: "", customHeaders: "" });
    return {
      isNew: true,
      mode: "catalog",
      id: norm.id,
      presetId: presetTpl.id,
      name: norm.name,
      protocol: norm.protocol,
      baseUrl: norm.baseUrl,
      exactEndpoint: false,
      apiKey: "",
      customHeaders: "",
      requiresKey: presetTpl.requiresKey !== false,
      selectedModelId: norm.models[0]?.id || "",
      models: norm.models.map((m) => ({ ...m, inputModalities: [...m.inputModalities] })),
      showKey: false,
      statusText: "",
      statusType: "",
      fetchMsg: "",
      fetchMsgType: "",
      fetching: false,
      testing: false,
    };
  }
  return {
    isNew: true,
    mode: "custom",
    id: "web-custom-" + Date.now(),
    presetId: "",
    name: "",
    protocol: "anthropic",
    baseUrl: "",
    exactEndpoint: false,
    apiKey: "",
    customHeaders: "",
    requiresKey: true,
    selectedModelId: "",
    models: [],
    showKey: false,
    statusText: "",
    statusType: "",
    fetchMsg: "",
    fetchMsgType: "",
    fetching: false,
    testing: false,
  };
}

function closeModelPickerModal() {
  state.pickerState = null;
  if ($("model-picker-modal")) $("model-picker-modal").hidden = true;
}

function renderModelPickerList() {
  const ps = state.pickerState;
  const listEl = $("mp-list");
  if (!ps || !listEl) return;
  const q = ps.query.trim().toLowerCase();
  const visible = q
    ? ps.candidates.filter((c) => c.id.toLowerCase().includes(q) || (c.name && c.name.toLowerCase().includes(q)))
    : ps.candidates;

  listEl.textContent = "";
  if (!visible.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.style.padding = "12px";
    empty.textContent = "没有匹配的模型。";
    listEl.appendChild(empty);
  } else {
    for (const c of visible) {
      const row = document.createElement("label");
      row.className = "dsh-picker-item";
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.checked = ps.selected.has(c.id);
      cb.addEventListener("change", () => {
        if (cb.checked) ps.selected.add(c.id);
        else ps.selected.delete(c.id);
        renderModelPickerList();
      });

      const meta = document.createElement("div");
      meta.className = "dsh-picker-meta";
      const idEl = document.createElement("b");
      idEl.textContent = c.id;
      meta.appendChild(idEl);
      if (c.name && c.name !== c.id) {
        const sub = document.createElement("small");
        sub.textContent = c.name;
        meta.appendChild(sub);
      }

      const badge = document.createElement("span");
      badge.className = "dsh-picker-badge";
      badge.textContent = c.inputModalities?.includes("image") ? "文本 · 图片" : "仅文本";
      row.append(cb, meta, badge);
      listEl.appendChild(row);
    }
  }
  if ($("mp-count")) $("mp-count").textContent = `已选 ${ps.selected.size} 个（共 ${ps.candidates.length} 个）`;
  if ($("btn-mp-confirm")) $("btn-mp-confirm").disabled = ps.selected.size === 0;
}

function openModelPickerModal(res) {
  const draft = state.editorDraft;
  if (!draft) return;
  const details = res.modelDetails?.length
    ? res.modelDetails
    : (res.models || []).map((id) => ({ id, name: "", inputModalities: ["text"] }));
  const existingIds = new Set(draft.models.map((m) => m.id.trim()).filter(Boolean));
  const selected = new Set();
  if (existingIds.size) {
    for (const c of details) {
      if (existingIds.has(c.id)) selected.add(c.id);
    }
  } else if (details.length <= 10) {
    for (const c of details) selected.add(c.id);
  } else {
    if (res.suggestedText) selected.add(res.suggestedText);
    if (res.suggestedVision) selected.add(res.suggestedVision);
    for (const c of details) {
      if (selected.size >= 8) break;
      if (!/(?:embedding|embed|whisper|tts|dall-e|moderation|rerank|bge-)/i.test(c.id)) {
        selected.add(c.id);
      }
    }
    if (!selected.size && details[0]) selected.add(details[0].id);
  }
  state.pickerState = { candidates: details, selected, query: "" };
  if ($("mp-search")) $("mp-search").value = "";
  if ($("model-picker-modal")) $("model-picker-modal").hidden = false;
  renderModelPickerList();
}

function adoptPickedModels() {
  const ps = state.pickerState;
  const draft = state.editorDraft;
  if (!ps || !draft) return;
  const candidateById = new Map(ps.candidates.map((c) => [c.id, c]));
  const keptRows = draft.models.filter((m) => {
    const id = m.id.trim();
    if (!candidateById.has(id)) return Boolean(id);
    return ps.selected.has(id);
  });
  const keptIds = new Set(keptRows.map((m) => m.id.trim()));
  const addedRows = ps.candidates
    .filter((c) => ps.selected.has(c.id) && !keptIds.has(c.id))
    .map((c) => ({
      id: c.id,
      name: c.name && c.name !== c.id ? c.name : "",
      inputModalities: c.inputModalities?.length ? [...c.inputModalities] : ["text"],
    }));
  draft.models = [...keptRows, ...addedRows];
  draft.fetchMsg = `✓ 已采用 ${draft.models.length} 个模型`;
  draft.fetchMsgType = "ok";
  closeModelPickerModal();
  renderProvidersPane();
}

async function fetchModelsIntoDraft(draft) {
  if (!draft || draft.fetching) return;
  if (!draft.baseUrl.trim()) {
    draft.fetchMsg = "请先填写 API 地址，再获取可用模型。";
    draft.fetchMsgType = "err";
    renderProvidersPane();
    return;
  }
  draft.fetching = true;
  draft.fetchMsg = "正在询问提供商获取模型列表…";
  draft.fetchMsgType = "";
  renderProvidersPane();
  try {
    const res = await fetchProviderModels(
      {
        protocol: draft.protocol,
        baseUrl: draft.baseUrl.trim(),
        exactEndpoint: Boolean(draft.exactEndpoint),
        apiKey: draft.apiKey.trim(),
        customHeaders: draft.customHeaders.trim(),
      },
      { fetchImpl: makeWebAiFetch() },
    );
    draft.fetching = false;
    draft.fetchMsg = `✓ 获取到 ${res.models.length} 个可用模型`;
    draft.fetchMsgType = "ok";
    renderProvidersPane();
    openModelPickerModal(res);
  } catch (err) {
    draft.fetching = false;
    draft.fetchMsg = "✗ " + (err?.message || err);
    draft.fetchMsgType = "err";
    renderProvidersPane();
  }
}

async function testDraftConnection(draft) {
  if (!draft || draft.testing) return;
  const preferred = draft.models.find((m) => m.id.trim() && m.id.trim() === draft.selectedModelId)?.id.trim();
  const firstModel = preferred || draft.models.find((m) => m.id.trim())?.id.trim() || "";
  if (!draft.baseUrl.trim()) {
    draft.statusText = "✗ 请先填写 API 地址";
    draft.statusType = "err";
    renderProvidersPane();
    return;
  }
  if (!firstModel) {
    draft.statusText = "✗ 请至少添加或获取一个模型后再测试连通";
    draft.statusType = "err";
    renderProvidersPane();
    return;
  }
  draft.testing = true;
  draft.statusText = `正在测试 ${firstModel} 连通性…`;
  draft.statusType = "";
  renderProvidersPane();
  try {
    const r = await testProviderConnection(
      {
        name: draft.name.trim() || "测试网关",
        protocol: draft.protocol,
        baseUrl: draft.baseUrl.trim(),
        exactEndpoint: Boolean(draft.exactEndpoint),
        apiKey: draft.apiKey.trim(),
        textModel: firstModel,
        customHeaders: draft.customHeaders.trim(),
      },
      { fetchImpl: makeWebAiFetch() },
    );
    draft.testing = false;
    draft.statusText = "✓ 连通成功：" + r.sample;
    draft.statusType = "ok";
  } catch (err) {
    draft.testing = false;
    draft.statusText = "✗ 失败：" + (err?.message || err);
    draft.statusType = "err";
  }
  renderProvidersPane();
}

function saveDraftProvider(draft) {
  if (!draft) return;
  const name = draft.name.trim();
  const baseUrl = draft.baseUrl.trim();
  const cleanModels = [];
  const seenIds = new Set();
  for (const m of draft.models) {
    const id = m.id.trim();
    if (!id) {
      draft.statusText = "✗ 存在空的模型 ID，请填写或移除空行";
      draft.statusType = "err";
      renderProvidersPane();
      return;
    }
    if (seenIds.has(id)) {
      draft.statusText = `✗ 模型 ID 重复：${id}`;
      draft.statusType = "err";
      renderProvidersPane();
      return;
    }
    seenIds.add(id);
    cleanModels.push(normalizeModelRow(m));
  }
  if (!name) {
    draft.statusText = "✗ 请填写提供商名称";
    draft.statusType = "err";
    renderProvidersPane();
    return;
  }
  if (!/^https?:\/\/\S+/i.test(baseUrl)) {
    draft.statusText = "✗ 请填写合法的 http:// 或 https:// API 地址";
    draft.statusType = "err";
    renderProvidersPane();
    return;
  }
  if (!cleanModels.length) {
    draft.statusText = "✗ 请至少添加一个模型（可点「获取可用模型」或「添加模型」）";
    draft.statusType = "err";
    renderProvidersPane();
    return;
  }

  const saved = normalizeWebProvider({
    id: draft.id,
    name,
    protocol: draft.protocol,
    baseUrl,
    exactEndpoint: draft.exactEndpoint,
    apiKey: draft.apiKey.trim(),
    customHeaders: draft.customHeaders.trim(),
    requiresKey: draft.requiresKey,
    models: cleanModels,
  });

  const idx = state.providers.findIndex((p) => p.id === saved.id);
  if (idx >= 0) state.providers[idx] = saved;
  else state.providers.push(saved);

  if (draft.isNew || state.activeProviderId === saved.id || draft.selectedModelId) {
    state.activeProviderId = saved.id;
    const preferred = saved.models.find((m) => m.id === draft.selectedModelId)?.id;
    state.activeModelId = preferred || saved.models[0]?.id || "";
  }
  saveProviders();
  state.expandedProviderId = null;
  state.addProviderOpen = false;
  state.editorDraft = null;
  state.savedProviderNotice = `✓ 已保存 ${saved.name}。`;
  renderProvidersPane();
  showToast(`已保存模型提供商：${saved.name}`);
}

function buildDshEditorCard(draft) {
  const wrap = document.createElement("div");
  wrap.className = "dsh-inset-editor";

  if (draft.isNew) {
    const tabs = document.createElement("div");
    tabs.className = "dsh-mode-tabs";
    for (const [mKey, mLbl] of [["catalog", "第三方模型提供商"], ["custom", "自定义模型 API"]]) {
      const tb = document.createElement("button");
      tb.type = "button";
      tb.className = "dsh-mode-tab" + (draft.mode === mKey ? " active" : "");
      tb.textContent = mLbl;
      tb.addEventListener("click", () => {
        if (draft.mode === mKey) return;
        const tpl = PRESET_PROVIDERS.find((x) => x.id === (draft.presetId || PRESET_PROVIDERS[0].id)) || PRESET_PROVIDERS[0];
        state.addProviderMode = mKey;
        state.editorDraft = createDraftForAdd(mKey, tpl);
        renderProvidersPane();
      });
      tabs.appendChild(tb);
    }
    const hint = document.createElement("p");
    hint.className = "dsh-hint";
    hint.textContent =
      draft.mode === "catalog"
        ? "从内置目录选择主流厂商，填入 API 密钥并按需获取或调整模型列表即可使用。"
        : "连接中转站、自部署服务或其他兼容 OpenAI / Anthropic / Gemini 协议的接口（支持直接填 http:// 地址）。";
    wrap.append(tabs, hint);

    if (draft.mode === "catalog") {
      const presetField = document.createElement("div");
      presetField.className = "field";
      const lbl = document.createElement("label");
      lbl.textContent = "选择内置厂商模板";
      const ps = document.createElement("select");
      for (const tpl of PRESET_PROVIDERS) {
        const o = document.createElement("option");
        o.value = tpl.id;
        o.textContent = `${tpl.name} · ${protocolLabel(tpl.protocol)}`;
        ps.appendChild(o);
      }
      ps.value = draft.presetId || PRESET_PROVIDERS[0].id;
      ps.addEventListener("change", () => {
        const tpl = PRESET_PROVIDERS.find((x) => x.id === ps.value);
        if (tpl) {
          state.editorDraft = createDraftForAdd("catalog", tpl);
          renderProvidersPane();
        }
      });
      presetField.append(lbl, ps);
      wrap.appendChild(presetField);
    }
  }

  const row1 = document.createElement("div");
  row1.className = "grid-two";

  const nameField = document.createElement("label");
  nameField.className = "field";
  const nameSpan = document.createElement("span");
  nameSpan.textContent = "提供商名称 *";
  const nameInput = document.createElement("input");
  nameInput.type = "text";
  nameInput.placeholder = "例如：我的自建网关 / OpenAI";
  nameInput.value = draft.name;
  nameInput.addEventListener("input", () => { draft.name = nameInput.value; });
  nameField.append(nameSpan, nameInput);

  const protoField = document.createElement("label");
  protoField.className = "field";
  const protoSpan = document.createElement("span");
  protoSpan.textContent = "接口协议 *";
  const protoSel = document.createElement("select");
  for (const [val, txt] of [["anthropic", "Anthropic Messages"], ["openai-compatible", "OpenAI 兼容"], ["gemini", "Google Gemini"]]) {
    const opt = document.createElement("option");
    opt.value = val;
    opt.textContent = txt;
    protoSel.appendChild(opt);
  }
  protoSel.value = draft.protocol;
  protoSel.addEventListener("change", () => {
    draft.protocol = protoSel.value;
    urlInput.placeholder = BASE_URL_HINTS[draft.protocol] || BASE_URL_HINTS["openai-compatible"];
  });
  protoField.append(protoSpan, protoSel);
  row1.append(nameField, protoField);

  const urlField = document.createElement("label");
  urlField.className = "field";
  const urlSpan = document.createElement("span");
  urlSpan.textContent = "API 地址 *";
  const urlInput = document.createElement("input");
  urlInput.type = "url";
  urlInput.spellcheck = false;
  urlInput.placeholder = BASE_URL_HINTS[draft.protocol] || BASE_URL_HINTS["openai-compatible"];
  urlInput.value = draft.baseUrl;
  urlInput.addEventListener("input", () => { draft.baseUrl = urlInput.value; });
  urlField.append(urlSpan, urlInput);

  const keyField = document.createElement("div");
  keyField.className = "field";
  const keyLbl = document.createElement("label");
  keyLbl.textContent = "API 密钥";
  const keyWrap = document.createElement("div");
  keyWrap.className = "dsh-key-wrap";
  const keyInput = document.createElement("input");
  keyInput.type = draft.showKey ? "text" : "password";
  keyInput.autocomplete = "new-password";
  keyInput.spellcheck = false;
  keyInput.placeholder = draft.requiresKey === false ? "本地免密服务可留空" : "输入 API 密钥";
  keyInput.value = draft.apiKey;
  keyInput.addEventListener("input", () => { draft.apiKey = keyInput.value; });
  const keyToggle = document.createElement("button");
  keyToggle.type = "button";
  keyToggle.className = "ghost small dsh-key-toggle";
  keyToggle.textContent = draft.showKey ? "隐藏密钥" : "显示密钥";
  keyToggle.addEventListener("click", () => {
    draft.showKey = !draft.showKey;
    renderProvidersPane();
  });
  keyWrap.append(keyInput, keyToggle);
  keyField.append(keyLbl, keyWrap);

  // DSH ModelListEditor
  const modelsSec = document.createElement("div");
  modelsSec.className = "dsh-models-section";
  const modelsHead = document.createElement("div");
  modelsHead.className = "dsh-models-head";
  const mhTitle = document.createElement("span");
  mhTitle.className = "dsh-models-head-title";
  mhTitle.textContent = `模型目录（${draft.models.length}）`;
  const mhActions = document.createElement("div");
  mhActions.className = "dsh-models-actions";

  const fetchBtn = document.createElement("button");
  fetchBtn.type = "button";
  fetchBtn.className = "ghost small";
  fetchBtn.disabled = draft.fetching;
  if (draft.fetching) {
    fetchBtn.textContent = "正在询问提供商…";
  } else {
    fetchBtn.append(svgIcon("search", "ic sm"), document.createTextNode("获取可用模型"));
  }
  fetchBtn.addEventListener("click", () => fetchModelsIntoDraft(draft));

  const addModelBtn = document.createElement("button");
  addModelBtn.type = "button";
  addModelBtn.className = "ghost small";
  addModelBtn.append(svgIcon("plus", "ic sm"), document.createTextNode("添加模型"));
  addModelBtn.addEventListener("click", () => {
    draft.models.push({ id: "", name: "", inputModalities: ["text"] });
    renderProvidersPane();
  });
  mhActions.append(fetchBtn, addModelBtn);
  modelsHead.append(mhTitle, mhActions);
  modelsSec.appendChild(modelsHead);

  if (draft.fetchMsg) {
    const fmsg = document.createElement("div");
    fmsg.className = `dsh-editor-status ${draft.fetchMsgType}`;
    fmsg.textContent = draft.fetchMsg;
    modelsSec.appendChild(fmsg);
  }

  const mList = document.createElement("div");
  mList.className = "dsh-model-list";
  if (!draft.models.length) {
    const emptyHint = document.createElement("p");
    emptyHint.className = "dsh-hint";
    emptyHint.textContent = "尚未添加模型：点击右上角「获取可用模型」自动拉取勾选，或点「添加模型」手动填写。";
    mList.appendChild(emptyHint);
  } else {
    draft.models.forEach((m, idx) => {
      const mId = m.id.trim();
      const isChosen = Boolean(mId) && (draft.selectedModelId ? draft.selectedModelId === mId : idx === 0);
      const mRow = document.createElement("div");
      mRow.className = "dsh-model-row" + (isChosen ? " active-model-row" : "");
      const top = document.createElement("div");
      top.className = "dsh-model-row-top";

      const inputs = document.createElement("div");
      inputs.className = "dsh-model-row-inputs";
      const idIn = document.createElement("input");
      idIn.type = "text";
      idIn.placeholder = "模型 ID（如 deepseek-v4.1-flash）";
      idIn.value = m.id;
      idIn.addEventListener("input", () => {
        if (draft.selectedModelId === m.id.trim()) draft.selectedModelId = idIn.value.trim();
        m.id = idIn.value;
      });
      const nmIn = document.createElement("input");
      nmIn.type = "text";
      nmIn.placeholder = "显示名称（留空使用模型 ID）";
      nmIn.value = m.name;
      nmIn.addEventListener("input", () => { m.name = nmIn.value; });
      inputs.append(idIn, nmIn);

      const checks = document.createElement("div");
      checks.className = "dsh-mod-checks";
      for (const [mod, lblTxt] of [["text", "文本"], ["image", "图片"]]) {
        const cLbl = document.createElement("label");
        cLbl.className = "dsh-mod-check";
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = m.inputModalities.includes(mod);
        cb.disabled = cb.checked && m.inputModalities.length === 1;
        cb.addEventListener("change", () => {
          const next = ["text", "image"].filter((x) => (x === mod ? cb.checked : m.inputModalities.includes(x)));
          if (next.length) m.inputModalities = next;
          renderProvidersPane();
        });
        cLbl.append(cb, document.createTextNode(lblTxt));
        checks.appendChild(cLbl);
      }

      const useModelBtn = document.createElement("button");
      useModelBtn.type = "button";
      useModelBtn.className = isChosen ? "ghost small active-tag" : "ghost small";
      if (isChosen) {
        useModelBtn.append(svgIcon("star", "ic sm", { filled: true }), document.createTextNode("使用中"));
      } else {
        useModelBtn.textContent = "设为当前";
      }
      useModelBtn.disabled = isChosen || !mId;
      useModelBtn.title = "将此具体模型设为当前默认（同时用于测试连通）";
      useModelBtn.addEventListener("click", () => {
        if (!m.id.trim()) return;
        draft.selectedModelId = m.id.trim();
        if (!draft.isNew) {
          const existing = state.providers.find((x) => x.id === draft.id);
          if (existing && existing.models?.some((em) => em.id === draft.selectedModelId)) {
            state.activeProviderId = draft.id;
            state.activeModelId = draft.selectedModelId;
            saveProviders();
          }
        }
        renderProvidersPane();
      });

      const upBtn = document.createElement("button");
      upBtn.type = "button";
      upBtn.className = "dsh-icon-btn";
      upBtn.appendChild(svgIcon("arrowUp", "ic sm"));
      upBtn.title = "上移";
      upBtn.disabled = idx === 0;
      upBtn.addEventListener("click", () => {
        [draft.models[idx - 1], draft.models[idx]] = [draft.models[idx], draft.models[idx - 1]];
        renderProvidersPane();
      });

      const dnBtn = document.createElement("button");
      dnBtn.type = "button";
      dnBtn.className = "dsh-icon-btn";
      dnBtn.appendChild(svgIcon("arrowDown", "ic sm"));
      dnBtn.title = "下移";
      dnBtn.disabled = idx === draft.models.length - 1;
      dnBtn.addEventListener("click", () => {
        [draft.models[idx], draft.models[idx + 1]] = [draft.models[idx + 1], draft.models[idx]];
        renderProvidersPane();
      });

      const rmBtn = document.createElement("button");
      rmBtn.type = "button";
      rmBtn.className = "dsh-icon-btn danger";
      rmBtn.appendChild(svgIcon("x", "ic sm"));
      rmBtn.title = "移除模型";
      rmBtn.addEventListener("click", () => {
        draft.models.splice(idx, 1);
        renderProvidersPane();
      });

      top.append(inputs, checks, useModelBtn, upBtn, dnBtn, rmBtn);
      mRow.appendChild(top);
      mList.appendChild(mRow);
    });
  }
  modelsSec.appendChild(mList);

  const adv = document.createElement("details");
  adv.className = "dsh-advanced";
  if (draft.exactEndpoint || draft.customHeaders) adv.open = true;
  const advSum = document.createElement("summary");
  advSum.textContent = "高级选项（精确端点与自定义请求头）";
  const exactRow = document.createElement("label");
  exactRow.className = "check-row";
  const exactCb = document.createElement("input");
  exactCb.type = "checkbox";
  exactCb.checked = draft.exactEndpoint;
  exactCb.addEventListener("change", () => { draft.exactEndpoint = exactCb.checked; });
  exactRow.append(exactCb, document.createTextNode("完整精确端点（不再自动拼接 /v1/...）"));
  const hdrField = document.createElement("label");
  hdrField.className = "field";
  hdrField.style.marginBottom = "0";
  const hdrSpan = document.createElement("span");
  hdrSpan.textContent = "自定义请求头 JSON";
  const hdrIn = document.createElement("input");
  hdrIn.type = "text";
  hdrIn.spellcheck = false;
  hdrIn.placeholder = '{"X-Tenant":"my-team"}';
  hdrIn.value = draft.customHeaders;
  hdrIn.addEventListener("input", () => { draft.customHeaders = hdrIn.value; });
  hdrField.append(hdrSpan, hdrIn);
  adv.append(advSum, exactRow, hdrField);

  const footer = document.createElement("div");
  footer.className = "dsh-editor-footer";
  const statusEl = document.createElement("div");
  statusEl.className = `dsh-editor-status ${draft.statusType}`;
  statusEl.textContent = draft.statusText || "";

  const btns = document.createElement("div");
  btns.className = "dsh-editor-btns";
  const testBtn = document.createElement("button");
  testBtn.type = "button";
  testBtn.className = "ghost small";
  testBtn.disabled = draft.testing;
  if (draft.testing) {
    testBtn.textContent = "测试中…";
  } else {
    testBtn.append(svgIcon("zap", "ic sm"), document.createTextNode("测试连通"));
  }
  testBtn.addEventListener("click", () => testDraftConnection(draft));

  const cancelBtn = document.createElement("button");
  cancelBtn.type = "button";
  cancelBtn.className = "ghost";
  cancelBtn.textContent = "取消";
  cancelBtn.addEventListener("click", () => {
    state.expandedProviderId = null;
    state.addProviderOpen = false;
    state.editorDraft = null;
    renderProvidersPane();
  });

  const saveBtn = document.createElement("button");
  saveBtn.type = "button";
  saveBtn.className = "primary";
  saveBtn.textContent = "保存";
  saveBtn.addEventListener("click", () => saveDraftProvider(draft));

  btns.append(testBtn, cancelBtn, saveBtn);
  footer.append(statusEl, btns);

  wrap.append(row1, urlField, keyField, modelsSec, adv, footer);
  return wrap;
}

function renderProvidersPane() {
  renderActiveModelSelectors();
  const noticeEl = $("prov-saved-notice");
  if (noticeEl) {
    noticeEl.hidden = !state.savedProviderNotice;
    noticeEl.textContent = state.savedProviderNotice || "";
  }

  const rowsEl = $("prov-rows");
  if (!rowsEl) return;
  rowsEl.textContent = "";

  for (const p of state.providers) {
    const li = document.createElement("li");
    const isExpanded = state.expandedProviderId === p.id && state.editorDraft && !state.editorDraft.isNew;
    const isActive = state.activeProviderId === p.id;
    const isPinnedVision = state.activeVisionProviderId === p.id && Boolean(state.activeVisionModelId);
    li.className = "dsh-row-card" + (isActive ? " active-card" : "");

    const head = document.createElement("div");
    head.className = "dsh-row-head";

    const identity = document.createElement("div");
    identity.className = "dsh-row-identity";
    const dot = document.createElement("span");
    dot.className = "dsh-dot " + (providerHasCredential(p) ? "configured" : "missing");
    dot.title = providerHasCredential(p) ? "API 密钥已配置" : "API 密钥缺失";
    const nm = document.createElement("span");
    nm.className = "dsh-row-name";
    nm.textContent = p.name;
    const protoTag = document.createElement("span");
    protoTag.className = "dsh-row-tag";
    protoTag.textContent = protocolLabel(p.protocol);
    const cntTag = document.createElement("span");
    cntTag.className = "dsh-row-tag";
    cntTag.textContent = `${p.models?.length || 0} 个模型`;
    identity.append(dot, nm, protoTag, cntTag);
    if (isActive && state.activeModelId) {
      const actTag = document.createElement("span");
      actTag.className = "dsh-row-tag active-tag";
      actTag.append(svgIcon("star", "ic sm", { filled: true }), document.createTextNode(`当前文本：${state.activeModelId}`));
      identity.appendChild(actTag);
    }
    if (isPinnedVision) {
      const visTag = document.createElement("span");
      visTag.className = "dsh-row-tag vision-tag";
      visTag.append(svgIcon("image", "ic sm"), document.createTextNode(`当前视觉：${state.activeVisionModelId}`));
      identity.appendChild(visTag);
    }

    const actions = document.createElement("div");
    actions.className = "dsh-row-actions";
    if (!isActive) {
      const useBtn = document.createElement("button");
      useBtn.type = "button";
      useBtn.className = "ghost small";
      useBtn.textContent = "设为默认";
      useBtn.addEventListener("click", () => {
        state.activeProviderId = p.id;
        state.activeModelId = p.models?.[0]?.id || "";
        state.savedProviderNotice = "";
        saveProviders();
        renderProvidersPane();
        showToast(`已切换默认提供商：${p.name}`);
      });
      actions.appendChild(useBtn);
    }
    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "ghost small";
    editBtn.textContent = isExpanded ? "收起" : "编辑";
    editBtn.addEventListener("click", () => {
      state.savedProviderNotice = "";
      state.addProviderOpen = false;
      if (isExpanded) {
        state.expandedProviderId = null;
        state.editorDraft = null;
      } else {
        state.expandedProviderId = p.id;
        state.editorDraft = createDraftFromProvider(p);
      }
      renderProvidersPane();
    });
    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "ghost small danger";
    delBtn.textContent = "删除";
    delBtn.disabled = state.providers.length <= 1;
    delBtn.addEventListener("click", () => {
      if (state.providers.length <= 1) return showToast("至少保留一个模型提供商");
      if (!confirm(`确定删除模型提供商「${p.name}」吗？`)) return;
      state.providers = state.providers.filter((x) => x.id !== p.id);
      if (state.activeProviderId === p.id) {
        state.activeProviderId = state.providers[0].id;
        state.activeModelId = state.providers[0].models?.[0]?.id || "";
      }
      if (state.expandedProviderId === p.id) {
        state.expandedProviderId = null;
        state.editorDraft = null;
      }
      saveProviders();
      renderProvidersPane();
      showToast(`已删除：${p.name}`);
    });
    actions.append(editBtn, delBtn);

    head.append(identity, actions);
    li.appendChild(head);
    if (isExpanded) li.appendChild(buildDshEditorCard(state.editorDraft));
    rowsEl.appendChild(li);
  }

  const addCard = $("prov-add-card");
  const openAddBtn = $("btn-prov-open-add");
  if (openAddBtn) openAddBtn.hidden = state.addProviderOpen;
  if (addCard) {
    addCard.textContent = "";
    addCard.hidden = !state.addProviderOpen;
    if (state.addProviderOpen && state.editorDraft?.isNew) {
      addCard.appendChild(buildDshEditorCard(state.editorDraft));
    }
  }
}

$("btn-prov-open-add")?.addEventListener("click", () => {
  state.savedProviderNotice = "";
  state.expandedProviderId = null;
  state.addProviderOpen = true;
  state.editorDraft = createDraftForAdd(state.addProviderMode, PRESET_PROVIDERS[0]);
  renderProvidersPane();
});
$("btn-open-providers").addEventListener("click", () => {
  state.savedProviderNotice = "";
  state.addProviderOpen = false;
  state.expandedProviderId = null;
  state.editorDraft = null;
  renderProvidersPane();
  showRightPane("providers");
});
$("btn-imp-manage-providers").addEventListener("click", () => $("btn-open-providers").click());
$("btn-prov-back").addEventListener("click", () => {
  renderImpProviderSelect();
  showRightPane("importer");
});
$("mp-search")?.addEventListener("input", () => {
  if (!state.pickerState) return;
  state.pickerState.query = $("mp-search").value;
  renderModelPickerList();
});
$("btn-mp-select-all")?.addEventListener("click", () => {
  const ps = state.pickerState;
  if (!ps) return;
  const q = ps.query.trim().toLowerCase();
  for (const c of ps.candidates) {
    if (!q || c.id.toLowerCase().includes(q) || (c.name && c.name.toLowerCase().includes(q))) {
      ps.selected.add(c.id);
    }
  }
  renderModelPickerList();
});
$("btn-mp-clear-all")?.addEventListener("click", () => {
  const ps = state.pickerState;
  if (!ps) return;
  const q = ps.query.trim().toLowerCase();
  for (const c of ps.candidates) {
    if (!q || c.id.toLowerCase().includes(q) || (c.name && c.name.toLowerCase().includes(q))) {
      ps.selected.delete(c.id);
    }
  }
  renderModelPickerList();
});
$("btn-mp-confirm")?.addEventListener("click", adoptPickedModels);
$("btn-mp-cancel")?.addEventListener("click", closeModelPickerModal);
$("btn-mp-close")?.addEventListener("click", closeModelPickerModal);

$("btn-open-settings").addEventListener("click", () => {
  if ($("st-cur-ver")) $("st-cur-ver").textContent = `v${WEB_APP_VERSION}`;
  if ($("st-theme")) $("st-theme").value = state.prefs.theme || "dark";
  if ($("st-update-url")) $("st-update-url").value = state.prefs.updateManifestUrl || "";
  if ($("st-keep-signed-in")) $("st-keep-signed-in").checked = state.prefs.keepSignedIn !== false;
  $("st-lock-mins").value = state.prefs.lockMinutes ?? 0;
  $("st-clip-sec").value = state.prefs.clipboardClearSeconds ?? 30;
  showRightPane("settings");
});
$("st-theme")?.addEventListener("change", () => {
  const preview = $("st-theme").value;
  if (VALID_THEMES.has(preview)) applyTheme(preview);
});
$("btn-st-check-update")?.addEventListener("click", async () => {
  savePrefs({ updateManifestUrl: ($("st-update-url")?.value || "").trim() });
  openDownloadsPane();
});
$("btn-st-close").addEventListener("click", () => {
  applyTheme(state.prefs.theme || "dark");
  if (state.selectedId) openDetail(state.selectedId);
  else showRightPane("welcome");
});
$("btn-st-save").addEventListener("click", () => {
  const keepSignedIn = $("st-keep-signed-in") ? $("st-keep-signed-in").checked : true;
  const theme = VALID_THEMES.has($("st-theme")?.value) ? $("st-theme").value : (state.prefs.theme || "dark");
  savePrefs({
    theme,
    keepSignedIn,
    lockMinutes: Math.max(0, Math.min(1440, Number($("st-lock-mins").value) || 0)),
    clipboardClearSeconds: Math.max(5, Math.min(300, Number($("st-clip-sec").value) || 30)),
    updateManifestUrl: ($("st-update-url")?.value || "").trim(),
  });
  applyTheme(theme);
  if (!keepSignedIn) clearPersistedWebSession();
  else if (state.session) persistWebSession(state.session);
  touchActivity();
  showToast("偏好设置已保存");
});

async function restoreWebSession() {
  if (state.prefs.keepSignedIn === false) {
    showAuthView();
    return;
  }
  let saved = null;
  try {
    saved = JSON.parse(localStorage.getItem(SESSION_KEY) || "null");
  } catch {
    saved = null;
  }
  if (!saved?.userKeyB64 || !saved?.serverUrl || (!saved?.refreshToken && !saved?.accessToken)) {
    showAuthView();
    return;
  }
  const idleMins = Number(state.prefs.lockMinutes || 0);
  if (idleMins > 0 && saved.lastActiveAt && Date.now() - saved.lastActiveAt > idleMins * 60000) {
    clearPersistedWebSession();
    showAuthView();
    showToast("空闲超时，网页端已自动锁定");
    return;
  }

  let userKey;
  try {
    userKey = SymmetricCryptoKey.fromB64(saved.userKeyB64);
  } catch {
    clearPersistedWebSession();
    showAuthView();
    return;
  }

  state.session = {
    userKey,
    userId: saved.userId || "",
    keyId: saved.keyId || null,
    email: saved.email || "",
    serverUrl: saved.serverUrl,
    accessToken: saved.accessToken || "",
    refreshToken: saved.refreshToken || "",
    tokenExpiresAt: saved.tokenExpiresAt || 0,
  };

  $("auth-screen").hidden = true;
  $("workspace").hidden = false;
  $("sidebar-user-email").textContent = saved.email || "";
  showRightPane("welcome");
  showToast("正在恢复登录状态…");

  try {
    let token = await ensureAccessToken();
    const api = makeApiClient(state.session.serverUrl);
    let data;
    try {
      data = await api.sync(token);
    } catch (syncErr) {
      if (syncErr instanceof ApiError && syncErr.status === 401 && state.session.refreshToken) {
        state.session.tokenExpiresAt = 0;
        token = await ensureAccessToken();
        data = await api.sync(token);
      } else {
        throw syncErr;
      }
    }
    const vault = await decryptSync(data, state.session.userKey);
    if (!state.session) return;
    state.items = vault.items;
    state.folders = vault.folders;
    state.domains = vault.domains;
    touchActivity();
    persistWebSession(state.session);
    lastPersistTouchAt = Date.now();
    realtimeHub.connect(state.session.serverUrl, token);
    renderSidebarAndList();
    showRightPane("welcome");
  } catch (err) {
    const authRejected = err instanceof ApiError && (err.status === 400 || err.status === 401);
    if (authRejected) {
      clearPersistedWebSession();
      state.session = null;
      showAuthView();
      showToast("登录状态已过期，请重新解锁");
    } else {
      state.session = null;
      showAuthView();
      showToast("暂时无法连接服务器，网络恢复后刷新可自动登录");
    }
  }
}

/* ----------------------------------------------------- 启动 */
loadProviders();
restoreWebSession();
