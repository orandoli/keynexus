/**
 * KeyNexus 浏览器网页端（直接挂载在服务端首页 `/`）
 * - 纯浏览器标准 Fetch + WebCrypto AES-256-CBC/HMAC-SHA256 零知识加解密
 * - 完整包含：四态工作台、Authenticator 独立动态码竖栏、AI 多格式导密、四端客户端下载中心
 */

import { PwdsvApi, ApiError, parseTwoFactorProviders, normalizeServerUrl } from "./lib/api.js";
import { deriveMasterKey, hashMasterPassword, makeRegisterPayload } from "./lib/crypto.js";
import { unlockUserKey, decryptSync, buildLoginCipherPayload } from "./lib/vault.js";
import { generateTotp, parseTotp } from "./lib/totp.js";
import { resolveItemScope, SCOPE_LABELS } from "./lib/matcher.js";
import { generatePassword, estimateStrength } from "./lib/generator.js";
import { RealtimeHub } from "./lib/realtime.js";
import { PRESET_PROVIDERS, parsePasswordFile, testProviderConnection, fetchProviderModels } from "./lib/importer/index.js";
import { compareSemver, fetchReleaseCatalog, checkClientUpdate } from "./lib/updater.js";

const WEB_APP_VERSION = "2.0.5";
const PREFS_KEY = "pwdsv_web_prefs_v1";
const PROVIDERS_KEY = "pwdsv_web_ai_providers_v1";

function loadPrefs() {
  try {
    const raw = JSON.parse(localStorage.getItem(PREFS_KEY) || "{}");
    const prefs = {
      serverUrl: raw.serverUrl || window.location.origin,
      email: raw.email || "",
      deviceId: raw.deviceId || crypto.randomUUID(),
      lockMinutes: raw.lockMinutes ?? 30,
      clipboardClearSeconds: raw.clipboardClearSeconds ?? 30,
      updateManifestUrl: raw.updateManifestUrl || "",
    };
    localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
    return prefs;
  } catch {
    const prefs = {
      serverUrl: window.location.origin,
      email: "",
      deviceId: crypto.randomUUID(),
      lockMinutes: 30,
      clipboardClearSeconds: 30,
      updateManifestUrl: "",
    };
    localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
    return prefs;
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
  editingProviderId: null,
  previewItems: [],
  releaseManifest: null,
};

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
  const t = await api.refresh(s.refreshToken);
  s.accessToken = t.accessToken;
  s.refreshToken = t.refreshToken;
  s.tokenExpiresAt = Date.now() + (t.expiresIn || 3600) * 1000 - 60000;
  return s.accessToken;
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
      { key: "desktop", icon: "💻", title: "Windows 电脑端", ext: ".exe" },
      { key: "mobile", icon: "📱", title: "Android 手机端", ext: ".apk" },
      { key: "extension", icon: "🧩", title: "Chrome / Edge 插件", ext: ".zip" },
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
      b.textContent = `${d.icon} ${d.title}`;
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
      webBanner.textContent = `⬆ 检测到新版网页端 v${webVer}（当前运行 v${WEB_APP_VERSION}）：若从 GitHub 发版，请下载新版网页包更新服务端目录或刷新缓存。`;
    }

    const specs = [
      { key: "web", icon: "🌐", name: "Web 网页中枢（当前端）", desc: `当前运行 v${WEB_APP_VERSION}，可一键拉取新版网页静态包或直接刷新重载。` },
      { key: "desktop", icon: "💻", name: "Windows 桌面守护端", desc: "支持 Win32 前台应用监听、无焦点悬浮 HUD、Simulate 输入与应用内一键更新。" },
      { key: "mobile", icon: "📱", name: "Android 手机端 APK", desc: "支持拍照 AI 识密、系统级密码自动填充、指纹解锁与应用内一键更新。" },
      { key: "extension", icon: "🧩", name: "Chrome / Edge 浏览器扩展", desc: "支持网页自动填充/抓密、跨站搜索、右键菜单与更新提示。" },
    ];
    for (const s of specs) {
      const entry = data[s.key] || {};
      const card = document.createElement("div");
      card.className = "dl-card";
      const head = document.createElement("div");
      head.className = "dl-card-head";
      const b = document.createElement("b");
      b.textContent = `${s.icon} ${s.name}`;
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
        reloadBtn.textContent = "↻ 强制刷新网页";
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
          dlBtn.textContent = `⬇ 下载新版网页包 (${formatSize(entry.size)})`;
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
        btn.textContent = `⬇ 下载安装包 (${formatSize(entry.size)})`;
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

    savePrefs({ serverUrl, email });
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
const FILTER_TITLES = {
  all: "全部密码",
  universal: "🌐 三端通用账户",
  web: "🕸 网页端专属",
  desktop: "💻 电脑端专属",
  mobile: "📱 手机端专属",
  fav: "★ 星标收藏",
  totp: "⏱ Authenticator 验证器",
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
    lbl.textContent = "📁 " + (f.name || "未命名");
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
  $("list-filter-title").textContent =
    FILTER_TITLES[state.filter] ||
    (state.filter.startsWith("folder:")
      ? `📁 ${state.folders.find((x) => x.id === state.filter.slice(7))?.name || "文件夹"}`
      : "全部密码");
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
    top.textContent = (item.favorite ? "★ " : "") + (item.name || "(未命名)");
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
  $("btn-d-fav").textContent = item.favorite ? "★" : "☆";
  $("btn-d-fav").style.opacity = item.favorite ? "1" : "0.45";

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
          c.style.stroke = remaining <= 5 ? "#f59e0b" : "#34d399";
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
  showToast(nextFav ? "★ 已收藏" : "已取消收藏");
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
        ref.circleEl.style.stroke = remaining <= 5 ? "#f59e0b" : "#34d399";
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
    nm.textContent = (item.favorite ? "★ " : "") + (item.name || "(未命名)");
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
    btnDetail.textContent = "›";
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

function loadProviders() {
  try {
    const raw = JSON.parse(localStorage.getItem(PROVIDERS_KEY) || "null");
    if (raw?.providers?.length) {
      state.providers = raw.providers;
      state.activeProviderId = raw.activeProviderId || raw.providers[0].id;
      return;
    }
  } catch {}
  state.providers = [
    { ...PRESET_PROVIDERS[0], id: "web-deepseek", apiKey: "", customHeaders: "" },
    { ...PRESET_PROVIDERS[1], id: "web-qwen", apiKey: "", customHeaders: "" },
    { ...PRESET_PROVIDERS[2], id: "web-gemini", apiKey: "", customHeaders: "" },
  ];
  state.activeProviderId = state.providers[0].id;
}
function saveProviders() {
  localStorage.setItem(PROVIDERS_KEY, JSON.stringify({ activeProviderId: state.activeProviderId, providers: state.providers }));
}

function renderImpProviderSelect() {
  const sel = $("imp-provider-select");
  sel.textContent = "";
  for (const p of state.providers) {
    const o = document.createElement("option");
    o.value = p.id;
    o.textContent = `${p.name} · ${p.textModel || p.visionModel}`;
    sel.appendChild(o);
  }
  sel.value = state.activeProviderId;
}

$("btn-open-importer").addEventListener("click", () => { renderImpProviderSelect(); showRightPane("importer"); });
$("btn-empty-ai").addEventListener("click", () => { renderImpProviderSelect(); showRightPane("importer"); });
$("imp-provider-select").addEventListener("change", () => { state.activeProviderId = $("imp-provider-select").value; saveProviders(); });
$("btn-imp-pick-file").addEventListener("click", () => $("imp-file-input").click());
$("btn-imp-toggle-text").addEventListener("click", () => { $("imp-raw-text-box").hidden = !$("imp-raw-text-box").hidden; });

async function runImport(fileObj) {
  $("imp-error").hidden = true;
  $("imp-status").hidden = false;
  try {
    const prov = state.providers.find((p) => p.id === state.activeProviderId) || state.providers[0];
    const res = await parsePasswordFile(fileObj, {
      provider: prov,
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

function renderProvidersPane() {
  const ul = $("prov-list");
  ul.textContent = "";
  for (const p of state.providers) {
    const li = document.createElement("li");
    if (p.id === state.editingProviderId) li.classList.add("active");
    li.textContent = (p.id === state.activeProviderId ? "● " : "") + p.name;
    li.addEventListener("click", () => { state.editingProviderId = p.id; loadProviderForm(p); renderProvidersPane(); });
    ul.appendChild(li);
  }
  const ps = $("prov-preset-select");
  if (!ps.options.length) {
    for (const tpl of PRESET_PROVIDERS) {
      const o = document.createElement("option");
      o.value = tpl.id;
      o.textContent = tpl.name;
      ps.appendChild(o);
    }
  }
}
function resetWebDetectedModels() {
  if ($("p-models-datalist")) $("p-models-datalist").textContent = "";
  if ($("p-model-quick")) $("p-model-quick").textContent = "";
  if ($("p-model-picker-row")) $("p-model-picker-row").hidden = true;
}

function loadProviderForm(p) {
  if (!p) return;
  $("p-name").value = p.name || "";
  $("p-protocol").value = p.protocol || "openai-compatible";
  $("p-baseurl").value = p.baseUrl || "";
  $("p-exact").checked = Boolean(p.exactEndpoint);
  $("p-apikey").value = p.apiKey || "";
  $("p-text-model").value = p.textModel || "";
  $("p-vision-model").value = p.visionModel || "";
  $("p-headers").value = p.customHeaders || "";
  if ($("prov-msg")) $("prov-msg").textContent = "";
  resetWebDetectedModels();
}

let webDetectTimer = null;
let webDetectSeq = 0;
async function detectWebProviderModels(silent = false) {
  if (!silent && webDetectTimer) {
    clearTimeout(webDetectTimer);
    webDetectTimer = null;
  }
  const msgEl = $("prov-msg");
  const baseUrl = $("p-baseurl")?.value.trim() || "";
  if (!baseUrl) {
    if (!silent && msgEl) {
      msgEl.textContent = "请先填写 Base URL";
      msgEl.scrollIntoView?.({ block: "nearest" });
    }
    return;
  }
  const seq = ++webDetectSeq;
  const btn = $("btn-prov-detect");
  if (!silent && msgEl) {
    msgEl.textContent = "正在检测可用模型…";
    msgEl.scrollIntoView?.({ block: "nearest" });
  }
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
      { fetchImpl: makeWebAiFetch() },
    );
    if (seq !== webDetectSeq) return;
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
    if (msgEl) {
      msgEl.textContent = `✓ 检测到 ${res.models.length} 个模型（已自动填入推荐模型，也可从下方列表切换）`;
      msgEl.scrollIntoView?.({ block: "nearest" });
    }
  } catch (err) {
    if (seq === webDetectSeq && !silent && msgEl) {
      msgEl.textContent = "✗ 模型检测失败：" + (err?.message || err);
      msgEl.scrollIntoView?.({ block: "nearest" });
    }
  } finally {
    if (btn && seq === webDetectSeq) {
      btn.disabled = false;
      btn.textContent = "🔍 检测模型";
    }
  }
}

function scheduleWebModelDetect() {
  if (webDetectTimer) clearTimeout(webDetectTimer);
  const url = $("p-baseurl")?.value.trim() || "";
  const key = $("p-apikey")?.value.trim() || "";
  if (!/^https?:\/\/\S+/i.test(url)) return;
  if (!key && !/localhost|127\.0\.0\.1|:11434/i.test(url)) return;
  webDetectTimer = setTimeout(() => {
    webDetectTimer = null;
    detectWebProviderModels(true);
  }, 700);
}

$("btn-prov-detect")?.addEventListener("click", () => detectWebProviderModels(false));
$("p-baseurl")?.addEventListener("input", scheduleWebModelDetect);
$("p-apikey")?.addEventListener("input", scheduleWebModelDetect);
$("p-protocol")?.addEventListener("change", scheduleWebModelDetect);
$("btn-p-use-text")?.addEventListener("click", () => {
  const v = $("p-model-quick")?.value;
  if (v) $("p-text-model").value = v;
});
$("btn-p-use-vision")?.addEventListener("click", () => {
  const v = $("p-model-quick")?.value;
  if (v) $("p-vision-model").value = v;
});
$("btn-open-providers").addEventListener("click", () => {
  state.editingProviderId = state.activeProviderId || state.providers[0]?.id;
  loadProviderForm(state.providers.find((x) => x.id === state.editingProviderId));
  renderProvidersPane();
  showRightPane("providers");
});
$("btn-imp-manage-providers").addEventListener("click", () => $("btn-open-providers").click());
$("btn-prov-back").addEventListener("click", () => { renderImpProviderSelect(); showRightPane("importer"); });
$("btn-prov-new-custom").addEventListener("click", () => {
  state.editingProviderId = "web-custom-" + Date.now();
  loadProviderForm({ name: "自定义网关", protocol: "openai-compatible", baseUrl: "", apiKey: "", textModel: "" });
});
$("btn-prov-add-preset").addEventListener("click", () => {
  const tpl = PRESET_PROVIDERS.find((x) => x.id === $("prov-preset-select").value);
  if (!tpl) return;
  state.editingProviderId = "web-" + tpl.id + "-" + Date.now();
  loadProviderForm({ ...tpl, apiKey: "", customHeaders: "" });
});
$("prov-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const cfg = {
    id: state.editingProviderId || "web-" + Date.now(),
    name: $("p-name").value.trim(),
    protocol: $("p-protocol").value,
    baseUrl: $("p-baseurl").value.trim(),
    exactEndpoint: $("p-exact").checked,
    apiKey: $("p-apikey").value.trim(),
    textModel: $("p-text-model").value.trim(),
    visionModel: $("p-vision-model").value.trim(),
    customHeaders: $("p-headers").value.trim(),
  };
  const i = state.providers.findIndex((p) => p.id === cfg.id);
  if (i >= 0) state.providers[i] = cfg;
  else state.providers.push(cfg);
  state.activeProviderId = cfg.id;
  saveProviders();
  renderProvidersPane();
  showToast(`已启用模型源：${cfg.name}`);
});
$("btn-prov-test").addEventListener("click", async () => {
  $("prov-msg").textContent = "测试连接中…";
  try {
    const r = await testProviderConnection(
      {
        name: $("p-name").value, protocol: $("p-protocol").value, baseUrl: $("p-baseurl").value,
        exactEndpoint: $("p-exact").checked, apiKey: $("p-apikey").value, textModel: $("p-text-model").value, customHeaders: $("p-headers").value,
      },
      { fetchImpl: makeWebAiFetch() },
    );
    $("prov-msg").textContent = "✓ 连通成功：" + r.sample;
  } catch (err) {
    $("prov-msg").textContent = "✗ 失败：" + err.message;
  }
});
$("btn-prov-delete").addEventListener("click", () => {
  if (state.providers.length <= 1) return showToast("至少保留一个模型源");
  state.providers = state.providers.filter((p) => p.id !== state.editingProviderId);
  state.activeProviderId = state.providers[0].id;
  state.editingProviderId = state.activeProviderId;
  saveProviders();
  loadProviderForm(state.providers[0]);
  renderProvidersPane();
});

$("btn-open-settings").addEventListener("click", () => {
  if ($("st-cur-ver")) $("st-cur-ver").textContent = `v${WEB_APP_VERSION}`;
  if ($("st-update-url")) $("st-update-url").value = state.prefs.updateManifestUrl || "";
  $("st-lock-mins").value = state.prefs.lockMinutes ?? 30;
  $("st-clip-sec").value = state.prefs.clipboardClearSeconds ?? 30;
  showRightPane("settings");
});
$("btn-st-check-update")?.addEventListener("click", async () => {
  savePrefs({ updateManifestUrl: ($("st-update-url")?.value || "").trim() });
  openDownloadsPane();
});
$("btn-st-close").addEventListener("click", () => (state.selectedId ? openDetail(state.selectedId) : showRightPane("welcome")));
$("btn-st-save").addEventListener("click", () => {
  savePrefs({
    lockMinutes: Math.max(0, Math.min(1440, Number($("st-lock-mins").value) || 0)),
    clipboardClearSeconds: Math.max(5, Math.min(300, Number($("st-clip-sec").value) || 30)),
    updateManifestUrl: ($("st-update-url")?.value || "").trim(),
  });
  touchActivity();
  showToast("偏好设置已保存");
});

/* ----------------------------------------------------- 启动 */
loadProviders();
showAuthView();
