/**
 * 后台 service worker：所有网络请求、密钥运算、跨页面抓密暂存和实时推送都在这里。
 *
 * 设计要点：
 * - 主密码、masterKey 只存在内存里，落盘的只有解锁后的 userKey（chrome.storage.session，
 *   浏览器一关就没了）。
 * - 条目缓存与跨页面抓密暂存池同样放 storage.session，MV3 的 SW 被回收也能无缝恢复。
 * - 解锁后自动连接 /notifications/hub WebSocket，桌面端或网页端改了密码会自动同步。
 */

import { PwdsvApi, ApiError, parseTwoFactorProviders, normalizeServerUrl } from "./lib/api.js";
import { deriveMasterKey, hashMasterPassword, SymmetricCryptoKey } from "./lib/crypto.js";
import { unlockUserKey, decryptSync, buildLoginCipherPayload } from "./lib/vault.js";
import { generateTotp } from "./lib/totp.js";
import { filterForUrl, buildDomainGroups, rankCandidates, hostOf, hasAppUri, resolveItemScope, SCOPE_LABELS } from "./lib/matcher.js";
import { generatePassword, generatePin } from "./lib/generator.js";
import { RealtimeHub } from "./lib/realtime.js";
import { checkClientUpdate } from "./lib/updater.js";

const SETTINGS_KEY = "settings";
const SESSION_KEY = "session";
const DEVICE_KEY = "deviceId";
const PENDING_KEY = "pendingCaptures";
const PENDING_TTL_MS = 3 * 60 * 1000; // 分步登录 / 跳转后保存提示保留 3 分钟

const DEFAULT_SETTINGS = {
  serverUrl: "",
  email: "",
  lockMinutes: 15,
  autofillOnLoad: false,
  loginToast: true,      // 打开有匹配账号的登录页时右上角给轻提示
  savePrompt: true,      // 提交表单后提示保存 / 更新账号
  otpAutofill: true,     // 焦点进验证码框自动填 TOTP
  strictHost: false,     // true = 只认完全相同的主机名
  realtimeSync: true,    // 开启 WebSocket 实时同步
  neverSaveDomains: [],  // 用户点了「此站不再提示」的域名列表
  updateManifestUrl: "", // 自定义更新清单地址
};

// 测试钩子：允许测试注入自定义 fetch / WebSocket
let customFetchImpl = null;
let customWebSocketImpl = null;
export function __setTestTransports({ fetchImpl = null, WebSocketImpl = null } = {}) {
  customFetchImpl = fetchImpl;
  customWebSocketImpl = WebSocketImpl;
  realtimeHub.WebSocketImpl = WebSocketImpl || globalThis.WebSocket;
}

/* ------------------------------------------------------------------ 实时连接 */

const realtimeHub = new RealtimeHub({
  onSyncNeeded: async () => {
    const session = await readSession({ touch: false });
    if (!session) return;
    await syncNow(session);
  },
  onForceLogout: async () => {
    await clearSession();
  },
});

async function refreshRealtimeConnection(session) {
  const settings = await getSettings();
  if (!session || settings.realtimeSync === false) {
    realtimeHub.disconnect();
    return;
  }
  realtimeHub.connect(session.serverUrl, session.accessToken);
}

/* ------------------------------------------------------------------ 存储封装 */

async function getSettings() {
  const raw = await chrome.storage.local.get(SETTINGS_KEY);
  const stored = raw[SETTINGS_KEY] || {};
  return {
    ...DEFAULT_SETTINGS,
    ...stored,
    neverSaveDomains: Array.isArray(stored.neverSaveDomains) ? stored.neverSaveDomains : [],
  };
}

async function saveSettings(patch) {
  const next = { ...(await getSettings()), ...patch };
  await chrome.storage.local.set({ [SETTINGS_KEY]: next });
  const session = await readSession({ touch: false });
  if (session && patch.lockMinutes !== undefined) {
    session.lockMinutes = Number(next.lockMinutes ?? 15);
    session.lockAt = session.lockMinutes > 0 ? Date.now() + session.lockMinutes * 60000 : 0;
    await writeSession(session);
  }
  await refreshRealtimeConnection(session);
  return next;
}

async function getDeviceId() {
  const raw = await chrome.storage.local.get(DEVICE_KEY);
  if (raw[DEVICE_KEY]) return raw[DEVICE_KEY];
  const id = crypto.randomUUID();
  await chrome.storage.local.set({ [DEVICE_KEY]: id });
  return id;
}

async function readSession({ touch = true } = {}) {
  const raw = await chrome.storage.session.get(SESSION_KEY);
  const session = raw[SESSION_KEY] || null;
  if (!session) return null;

  if (session.lockAt && Date.now() > session.lockAt) {
    await clearSession();
    return null;
  }

  // 滑动续期：每次交互把锁定时间往后推
  const minutes = Number(session.lockMinutes ?? 0);
  if (touch && minutes > 0) {
    const next = Date.now() + minutes * 60000;
    if (next - (session.lockAt || 0) > 30000) {
      session.lockAt = next;
      await writeSession(session);
    }
  }
  return session;
}

async function writeSession(session) {
  await chrome.storage.session.set({ [SESSION_KEY]: session });
}

async function clearSession() {
  realtimeHub.disconnect();
  await chrome.storage.session.remove([SESSION_KEY, PENDING_KEY]);
}

/* -------------------------------------------------------- 跨页面抓密暂存池 */

async function readPendingMap() {
  const raw = await chrome.storage.session.get(PENDING_KEY);
  const map = raw[PENDING_KEY] || {};
  const now = Date.now();
  let dirty = false;
  for (const [k, v] of Object.entries(map)) {
    if (!v || now - (v.updatedAt || 0) > PENDING_TTL_MS) {
      delete map[k];
      dirty = true;
    }
  }
  if (dirty) await chrome.storage.session.set({ [PENDING_KEY]: map });
  return map;
}

async function writePendingEntry(tabKey, entry) {
  const map = await readPendingMap();
  if (!entry) delete map[tabKey];
  else map[tabKey] = { ...entry, updatedAt: Date.now() };
  await chrome.storage.session.set({ [PENDING_KEY]: map });
}

function tabSlotKey(sender, msg) {
  if (sender?.tab?.id !== undefined && sender?.tab?.id !== null) {
    return "tab:" + sender.tab.id;
  }
  return "url:" + (hostOf(msg?.url || "") || "global");
}

/* -------------------------------------------------------------- 会话与解密 */

function withTimeout(session) {
  const minutes = Number(session.lockMinutes ?? 0);
  return { ...session, lockAt: minutes > 0 ? Date.now() + minutes * 60000 : 0 };
}

async function makeApi(session, overrideServerUrl) {
  const settings = await getSettings();
  const serverUrl = normalizeServerUrl(overrideServerUrl || session?.serverUrl || settings.serverUrl);
  return new PwdsvApi(serverUrl, {
    deviceId: await getDeviceId(),
    deviceName: "PWDSV 浏览器插件",
    fetchImpl: customFetchImpl || undefined,
  });
}

/** 解锁：预登录 -> 派生 masterKey -> 登录 -> 同步 -> 解出 userKey 和条目 */
async function unlock({ email, password, serverUrl, twoFactorToken, twoFactorProvider }) {
  const settings = await getSettings();
  const base = normalizeServerUrl(serverUrl || settings.serverUrl);
  if (!base) throw new Error("还没填服务器地址，先去设置里填一下");

  const api = await makeApi(null, base);
  const kdf = await api.prelogin(email);

  const masterKey = await deriveMasterKey(password, email, kdf);
  const masterPasswordHash = await hashMasterPassword(masterKey, password);

  let tokens;
  try {
    tokens = await api.login({
      email,
      masterPasswordHash,
      twoFactorToken,
      twoFactorProvider,
    });
  } catch (e) {
    if (e instanceof ApiError && e.status === 400) {
      const providers = parseTwoFactorProviders(e);
      if (providers.length) {
        // 如果首选方式是邮箱验证码（1）且尚未填码，顺手触发服务端发信
        if (!twoFactorToken && providers.some((p) => p.id === 1) && !providers.some((p) => p.id === 0)) {
          api.sendEmailLoginOtp({ email, masterPasswordHash }).catch(() => {});
        }
        return { needsTwoFactor: true, providers };
      }
    }
    throw e;
  }

  const sync = await api.sync(tokens.accessToken);
  const { userKey } = await unlockUserKey(sync.profile, masterKey);
  const vault = await decryptSync(sync, userKey);

  const session = withTimeout({
    userKeyB64: userKey.toB64(),
    userId: sync.profile?.id || "",
    keyId: sync.userDecryption?.userKeyId || null,
    email,
    serverUrl: base,
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    tokenExpiresAt: Date.now() + (tokens.expiresIn || 3600) * 1000 - 60000,
    securityStamp: sync.profile?.securityStamp || "",
    lockMinutes: settings.lockMinutes,
    lastSync: Date.now(),
    items: vault.items,
    folders: vault.folders,
    domains: vault.domains,
  });

  await writeSession(session);
  await saveSettings({ serverUrl: base, email });
  await refreshRealtimeConnection(session);
  return { ok: true, email, itemCount: vault.items.length };
}

/** 主动触发邮箱两步验证码 */
async function sendEmailOtp({ email, password, serverUrl }) {
  const settings = await getSettings();
  const base = normalizeServerUrl(serverUrl || settings.serverUrl);
  const api = await makeApi(null, base);
  const kdf = await api.prelogin(email);
  const masterKey = await deriveMasterKey(password, email, kdf);
  const masterPasswordHash = await hashMasterPassword(masterKey, password);
  await api.sendEmailLoginOtp({ email, masterPasswordHash });
  return { ok: true };
}

/** 拿一个能用的 access token，过期就先刷新 */
async function ensureToken(session) {
  if (session.accessToken && Date.now() < (session.tokenExpiresAt || 0)) return session.accessToken;
  const api = await makeApi(session);
  try {
    const t = await api.refresh(session.refreshToken);
    session.accessToken = t.accessToken;
    session.refreshToken = t.refreshToken;
    session.tokenExpiresAt = Date.now() + (t.expiresIn || 3600) * 1000 - 60000;
    await writeSession(session);
    await refreshRealtimeConnection(session);
    return session.accessToken;
  } catch {
    await clearSession();
    throw new Error("登录状态过期了，请重新解锁");
  }
}

async function syncNow(session) {
  const api = await makeApi(session);
  const token = await ensureToken(session);
  const data = await api.sync(token);
  const vault = await decryptSync(data, keyFromSession(session));
  session.items = vault.items;
  session.folders = vault.folders;
  session.domains = vault.domains;
  session.lastSync = Date.now();
  await writeSession(session);
  return vault.items.length;
}

function keyFromSession(session) {
  return SymmetricCryptoKey.fromB64(session.userKeyB64);
}

/* ------------------------------------------------------------ 给页面用的查询 */

function domainGroups(session) {
  return buildDomainGroups(session.domains);
}

function matchOptions(settings, session) {
  return {
    defaultPolicy: settings.strictHost ? "host" : "baseDomain",
    domainGroups: domainGroups(session),
  };
}

function publicItem(item) {
  const pwdsvScope = resolveItemScope(item);
  return {
    id: item.id,
    name: item.name,
    username: item.username,
    uris: item.uris,
    folderId: item.folderId || null,
    folderName: item.folderName,
    favorite: item.favorite,
    type: item.type,
    typeName: item.typeName,
    pwdsvScope,
    scopeLabel: SCOPE_LABELS[pwdsvScope] || "三端通用",
    isApp: hasAppUri(item),
    hasTotp: Boolean(item.totp),
    status: item.status,
  };
}

/**
 * 校验并提取请求来源的真实页面 URL（防止恶意跨域 iframe 伪造 msg.url 骗自动填充）
 */
function effectivePageUrl(msg, sender) {
  if (sender?.url && /^https?:/i.test(sender.url)) {
    return sender.url;
  }
  return String(msg?.url || "");
}

async function findCandidates(url, session, limit = 8) {
  const settings = await getSettings();
  const options = matchOptions(settings, session);
  const matched = filterForUrl(session.items, url, options);
  const ranked = rankCandidates(matched, url);
  return ranked.slice(0, limit).map(publicItem);
}

/**
 * 分析捕获到的 (url, username, password) 该「新建」「更新已有」还是「完全一致跳过」
 */
function classifyCapture(session, settings, { url, username, password, title }) {
  const host = hostOf(url);
  if (!host || !password) return null;
  if ((settings.neverSaveDomains || []).includes(host)) return null;

  const matched = rankCandidates(
    filterForUrl(session.items, url, matchOptions(settings, session)),
    url,
  );

  const cleanUser = String(username || "").trim();

  // 1. 账号 + 密码都已经一模一样存在库里 -> 不用提示
  const exact = matched.find(
    (it) =>
      (!cleanUser || (it.username || "").toLowerCase() === cleanUser.toLowerCase()) &&
      (it.password || "") === password,
  );
  if (exact) return { action: "none", reason: "already-saved" };

  // 2. 同站点存在同用户名（或未抓到用户名但站点只有唯一账号），且密码变了 -> 提示更新原条目
  const sameAccount = cleanUser
    ? matched.find((it) => (it.username || "").toLowerCase() === cleanUser.toLowerCase())
    : matched.length === 1
      ? matched[0]
      : null;

  if (sameAccount) {
    return {
      action: "update",
      existingId: sameAccount.id,
      name: sameAccount.name || title || host,
      username: cleanUser || sameAccount.username || "",
      password,
      url,
      host,
    };
  }

  // 3. 新账号 -> 提示新建
  return {
    action: "create",
    existingId: null,
    name: (title && title.length <= 48 ? title : "") || host,
    username: cleanUser,
    password,
    url,
    host,
  };
}

/* ------------------------------------------------------------------ 消息路由 */

async function requireSession() {
  const session = await readSession();
  if (!session) throw new Error("locked");
  return session;
}

const handlers = {
  async status() {
    const settings = await getSettings();
    const session = await readSession();
    if (session) await refreshRealtimeConnection(session);
    return {
      locked: !session,
      email: session?.email || settings.email || "",
      serverUrl: session?.serverUrl || settings.serverUrl || "",
      itemCount: session?.items?.length ?? null,
      lastSync: session?.lastSync ?? null,
      lockMinutes: settings.lockMinutes,
    };
  },

  async unlock(msg) {
    return unlock(msg);
  },

  async sendEmailOtp(msg) {
    return sendEmailOtp(msg);
  },

  async lock() {
    await clearSession();
    return { ok: true };
  },

  async logout() {
    await clearSession();
    await chrome.storage.local.remove([SETTINGS_KEY]);
    return { ok: true };
  },

  async sync() {
    const session = await requireSession();
    const count = await syncNow(session);
    return { ok: true, itemCount: count };
  },

  async folders() {
    const session = await requireSession();
    return { folders: session.folders || [] };
  },

  /**
   * 列表查询：
   * - 有搜索词 query 时：默认在全库搜索（避免在 A 站搜不到 B 站的密码），同时把匹配当前网址的排前面
   * - scope === "all"：返回全库
   * - scope === "apps"：只返回含桌面应用 app:// 规则的记录
   * - 默认无 query 且传了 url（scope="site" 或未传）：返回当前站点匹配项，并附带 siteCount / total
   */
  async list(msg) {
    const session = await readSession();
    if (!session) return { locked: true, items: [], total: 0, siteCount: 0, appCount: 0 };
    const settings = await getSettings();
    const allItems = session.items || [];
    const options = matchOptions(settings, session);

    const siteMatched = msg.url ? rankCandidates(filterForUrl(allItems, msg.url, options), msg.url) : [];
    const appMatched = allItems.filter((it) => hasAppUri(it));
    const q = String(msg.query || "").trim().toLowerCase();
    const scope = msg.scope || (q ? "all" : msg.url ? "site" : "all");

    let items;
    if (scope === "site") {
      items = siteMatched;
    } else if (scope === "apps" || scope === "desktop") {
      items = allItems.filter((it) => resolveItemScope(it) === "desktop" || hasAppUri(it));
    } else if (scope === "mobile") {
      items = allItems.filter((it) => resolveItemScope(it) === "mobile");
    } else if (scope === "universal") {
      items = allItems.filter((it) => resolveItemScope(it) === "universal");
    } else {
      // 全库视图：当前站点匹配的置顶，收藏次之
      const siteIds = new Set(siteMatched.map((i) => i.id));
      items = [...allItems].sort((a, b) => {
        const sa = (siteIds.has(a.id) ? 4 : 0) + (a.favorite ? 2 : 0);
        const sb = (siteIds.has(b.id) ? 4 : 0) + (b.favorite ? 2 : 0);
        if (sb !== sa) return sb - sa;
        return String(a.name || "").localeCompare(String(b.name || ""), "zh-CN");
      });
    }

    if (q) {
      items = items.filter((it) =>
        [it.name, it.username, it.folderName, it.notes, ...(it.uris || []).map((u) => u.uri)]
          .join(" ")
          .toLowerCase()
          .includes(q),
      );
    }

    return {
      locked: false,
      items: items.map(publicItem),
      total: allItems.length,
      siteCount: siteMatched.length,
      appCount: appMatched.length,
      universalCount: allItems.filter((it) => resolveItemScope(it) === "universal").length,
      mobileCount: allItems.filter((it) => resolveItemScope(it) === "mobile").length,
      folders: session.folders || [],
    };
  },

  /** 取单个条目的完整详情（供弹窗详情页与编辑表单使用） */
  async getItem(msg) {
    const session = await requireSession();
    const item = (session.items || []).find((it) => it.id === msg.id);
    if (!item) throw new Error("找不到这条记录");
    let totpCode = "";
    let totpRemaining = 0;
    if (item.totp) {
      try {
        const r = await generateTotp(item.totp);
        totpCode = r.code;
        totpRemaining = r.remaining;
      } catch {
        totpCode = "";
      }
    }
    return {
      item: {
        id: item.id,
        name: item.name,
        username: item.username,
        password: item.password,
        totp: item.totp,
        notes: item.notes,
        uris: item.uris,
        folderId: item.folderId,
        folderName: item.folderName,
        favorite: item.favorite,
        pwdsvScope: resolveItemScope(item),
        scopeLabel: SCOPE_LABELS[resolveItemScope(item)] || "三端通用",
        isApp: hasAppUri(item),
        passwordHistoryCount: item.passwordHistory?.length || 0,
        totpCode,
        totpRemaining,
      },
    };
  },

  /** 取单个条目的明文字段（复制、填充都走这里） */
  async secret(msg) {
    const session = await requireSession();
    const item = (session.items || []).find((it) => it.id === msg.id);
    if (!item) throw new Error("找不到这条记录");
    if (msg.field === "totp") {
      if (!item.totp) throw new Error("这条记录没存验证码");
      const { code, remaining, period } = await generateTotp(item.totp);
      return { value: code, remaining, period };
    }
    const field = msg.field === "username" ? "username" : msg.field === "notes" ? "notes" : "password";
    return { value: item[field] || "" };
  },

  /** 给页面用的填充数据（带同源二次确认 + 若有 TOTP 顺带算好） */
  async fillData(msg, sender) {
    const session = await requireSession();
    const item = (session.items || []).find((it) => it.id === msg.id);
    if (!item) throw new Error("找不到这条记录");

    // 来自内容脚本时校验当前 frame 的 URL 与条目确实匹配（允许弹窗主动指定强制填充 force=true）
    if (sender?.tab && !msg.force) {
      const pageUrl = effectivePageUrl(msg, sender);
      const settings = await getSettings();
      const matched = filterForUrl([item], pageUrl, matchOptions(settings, session));
      if (!matched.length) throw new Error("当前页面域名与该密码条目不匹配，已拦截自动填充");
    }

    let totp = "";
    if (item.totp) {
      try {
        totp = (await generateTotp(item.totp)).code;
      } catch {
        totp = "";
      }
    }
    return { username: item.username || "", password: item.password || "", totp, name: item.name };
  },

  /** 输入框旁边那排候选 + 是否开启登录页右上角提示 */
  async candidates(msg, sender) {
    const settings = await getSettings();
    const session = await readSession();
    const url = effectivePageUrl(msg, sender);
    if (!session) return { locked: true, items: [], loginToast: false };
    return {
      locked: false,
      items: await findCandidates(url, session),
      loginToast: settings.loginToast !== false,
    };
  },

  /** 验证码框自动填：找当前网址最匹配、且带 TOTP 的那条 */
  async totpForUrl(msg, sender) {
    const settings = await getSettings();
    if (!settings.otpAutofill) return { code: "" };
    const session = await readSession();
    if (!session) return { code: "" };
    const url = effectivePageUrl(msg, sender);
    const matched = filterForUrl(session.items, url, matchOptions(settings, session));
    for (const item of rankCandidates(matched, url)) {
      if (!item.totp) continue;
      try {
        const { code, remaining } = await generateTotp(item.totp);
        return { code, remaining, name: item.name };
      } catch {
        continue;
      }
    }
    return { code: "" };
  },

  /** 分步登录第 1 步：先暂存当前标签页刚填的用户名 */
  async stageUsername(msg, sender) {
    const username = String(msg.username || "").trim();
    if (!username) return { staged: false };
    const slot = tabSlotKey(sender, msg);
    const map = await readPendingMap();
    const prev = map[slot] || {};
    await writePendingEntry(slot, {
      ...prev,
      stagedUsername: username,
      stagedHost: hostOf(effectivePageUrl(msg, sender)),
    });
    return { staged: true };
  },

  /**
   * 表单提交瞬间：同步暂存账号密码到后台会话池，这样就算页面立刻 302 跳转也不会丢！
   */
  async stageCapture(msg, sender) {
    const settings = await getSettings();
    if (!settings.savePrompt) return { prompt: false };
    const session = await readSession();
    if (!session) return { prompt: false, locked: true };

    const url = effectivePageUrl(msg, sender);
    const host = hostOf(url);
    const slot = tabSlotKey(sender, msg);
    const map = await readPendingMap();
    const prev = map[slot];

    // 若本页只输了密码（两步登录第 2 页），自动取回第 1 页暂存的同站点用户名
    let username = String(msg.username || "").trim();
    if (!username && prev?.stagedUsername && (!prev.stagedHost || prev.stagedHost === host)) {
      username = prev.stagedUsername;
    }

    const decision = classifyCapture(session, settings, {
      url,
      username,
      password: msg.password || "",
      title: msg.title || "",
    });

    if (!decision || decision.action === "none") {
      await writePendingEntry(slot, null);
      return { prompt: false, reason: decision?.reason || "ignored" };
    }

    await writePendingEntry(slot, { capture: decision });
    return { prompt: true, capture: decision };
  },

  /** 新页面加载或 SPA 路由切换后：检查本标签页是否有待确认保存的密码 */
  async checkPendingCapture(msg, sender) {
    const settings = await getSettings();
    if (!settings.savePrompt) return { capture: null };
    const session = await readSession({ touch: false });
    if (!session) return { capture: null };

    const slot = tabSlotKey(sender, msg);
    const map = await readPendingMap();
    const entry = map[slot];
    if (!entry?.capture) return { capture: null };

    // 重新跟最新库核对一次，如果已经保存过了就自动清掉
    const recheck = classifyCapture(session, settings, entry.capture);
    if (!recheck || recheck.action === "none") {
      await writePendingEntry(slot, null);
      return { capture: null };
    }
    return { capture: recheck };
  },

  async dismissPendingCapture(msg, sender) {
    const slot = tabSlotKey(sender, msg);
    await writePendingEntry(slot, null);
    return { ok: true };
  },

  async neverSaveDomain(msg, sender) {
    const host = hostOf(msg.url || effectivePageUrl(msg, sender)) || String(msg.host || "").toLowerCase();
    if (host) {
      const settings = await getSettings();
      const set = new Set(settings.neverSaveDomains || []);
      set.add(host);
      await saveSettings({ neverSaveDomains: [...set] });
    }
    await writePendingEntry(tabSlotKey(sender, msg), null);
    return { ok: true, host };
  },

  /** 兼容旧调用：直接询问是否需要提示保存 */
  async askSave(msg, sender) {
    const settings = await getSettings();
    if (!settings.savePrompt) return { prompt: false };
    const session = await readSession();
    if (!session) return { prompt: false };

    const decision = classifyCapture(session, settings, {
      url: effectivePageUrl(msg, sender),
      username: msg.username || "",
      password: msg.password || "",
      title: msg.title || "",
    });
    if (!decision || decision.action === "none") {
      return { prompt: false, reason: decision?.reason || "already-saved" };
    }
    return {
      prompt: true,
      existing: decision.action === "update",
      existingId: decision.existingId,
      capture: decision,
    };
  },

  /**
   * 统一保存入口：支持「新建条目」与「编辑 / 更新已有条目」（弹窗手动提交、网页抓密横幅共用）
   */
  async save(msg, sender) {
    const session = await requireSession();
    const api = await makeApi(session);
    const token = await ensureToken(session);

    const targetId = msg.id || msg.existingId || null;
    const existingItem = targetId ? (session.items || []).find((it) => it.id === targetId) : null;

    // 若是在网页横幅点「更新密码」，把新网址（若原本没有）一并保留在原条目的 uris 里
    let uris = msg.uris || null;
    if (!uris && existingItem && msg.url) {
      const hasSameHost = (existingItem.uris || []).some((u) => hostOf(u.uri) === hostOf(msg.url));
      uris = hasSameHost ? existingItem.uris : [...(existingItem.uris || []), { uri: msg.url, match: null }];
    }

    const fallbackName = (() => {
      if (msg.name) return msg.name;
      if (existingItem?.name) return existingItem.name;
      try {
        return new URL(msg.url).hostname;
      } catch {
        return "未命名条目";
      }
    })();

    const payload = await buildLoginCipherPayload(
      {
        name: fallbackName,
        username: msg.username ?? existingItem?.username ?? "",
        password: msg.password ?? existingItem?.password ?? "",
        totp: msg.totp !== undefined ? msg.totp : existingItem?.totp || "",
        uri: msg.url || msg.uri || "",
        uris,
        notes: msg.notes !== undefined ? msg.notes : existingItem?.notes || "",
        folderId: msg.folderId !== undefined ? msg.folderId : existingItem?.folderId || null,
        favorite: msg.favorite !== undefined ? Boolean(msg.favorite) : Boolean(existingItem?.favorite),
        fields: msg.fields !== undefined ? msg.fields : existingItem?.fields,
        pwdsvScope: msg.pwdsvScope || existingItem?.pwdsvScope || null,
        pwdsvOriginDevice: msg.pwdsvOriginDevice || "web",
      },
      {
        userKey: keyFromSession(session),
        userId: session.userId,
        keyId: session.keyId,
        existingItem,
      },
    );

    let saved;
    if (existingItem) {
      saved = await api.updateCipher(token, existingItem.id, payload);
    } else {
      saved = await api.createCipher(token, payload);
    }

    await writePendingEntry(tabSlotKey(sender, msg), null);
    await syncNow(session);
    return { ok: true, id: saved?.id || existingItem?.id || null, updated: Boolean(existingItem) };
  },

  async deleteCipher(msg) {
    const session = await requireSession();
    const api = await makeApi(session);
    const token = await ensureToken(session);
    if (!msg.id) throw new Error("缺少条目 ID");
    await api.deleteCipher(token, msg.id);
    await syncNow(session);
    return { ok: true };
  },

  async settings(msg) {
    if (msg.patch) await saveSettings(msg.patch);
    return getSettings();
  },

  async generate(msg) {
    if (msg.kind === "pin") return { value: generatePin(msg.length || 6) };
    return {
      value: generatePassword({
        length: msg.length || 20,
        symbols: msg.symbols !== false,
        digits: msg.digits !== false,
        upper: msg.upper !== false,
        lower: msg.lower !== false,
      }),
    };
  },

  /** 测试服务器连通性 */
  async ping(msg) {
    const base = normalizeServerUrl(msg.serverUrl || (await getSettings()).serverUrl);
    if (!base) throw new Error("先填服务器地址");
    const api = await makeApi(null, base);
    const cfg = await api.config();
    return { ok: true, version: cfg?.version || cfg?.server?.version || "" };
  },

  /** 检查扩展新版本（从服务器 /client-releases/latest.json 或自定义清单拉取） */
  async checkUpdate(msg) {
    const settings = await getSettings();
    const serverUrl = normalizeServerUrl(msg?.serverUrl || settings.serverUrl || "");
    const customManifestUrl =
      msg?.customManifestUrl !== undefined ? msg.customManifestUrl : settings.updateManifestUrl || "";
    const currentVersion = chrome.runtime.getManifest?.().version || "2.0.9";
    return checkClientUpdate({
      platform: "extension",
      currentVersion,
      serverUrl,
      customManifestUrl,
      fetchImpl: customFetchImpl || fetch,
    });
  },
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const fn = handlers[msg?.type];
  if (!fn) {
    sendResponse({ error: "未知消息：" + msg?.type });
    return false;
  }
  Promise.resolve()
    .then(() => fn(msg, sender))
    .then((data) => sendResponse({ ...data, ok: data?.ok ?? true }))
    .catch((e) => {
      const message = String(e?.message || e);
      sendResponse({ error: message === "locked" ? "locked" : message });
    });
  return true;
});

/* ------------------------------------------------------------ 快捷键 / 菜单 */

chrome.commands?.onCommand.addListener(async (command) => {
  if (command !== "fill_login") return;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;
  chrome.tabs.sendMessage(tab.id, { type: "cmd:fill" }).catch(() => {});
});

chrome.runtime.onInstalled.addListener(async () => {
  const settings = await getSettings();
  await saveSettings(settings);
  chrome.contextMenus?.removeAll?.(() => {
    chrome.contextMenus?.create({
      id: "pwdsv-root",
      title: "KeyNexus",
      contexts: ["page", "editable"],
    });
    chrome.contextMenus?.create({
      id: "pwdsv-fill",
      parentId: "pwdsv-root",
      title: "填充当前网站账号密码",
      contexts: ["page", "editable"],
    });
    chrome.contextMenus?.create({
      id: "pwdsv-gen-fill",
      parentId: "pwdsv-root",
      title: "生成随机强密码并填入输入框",
      contexts: ["editable"],
    });
    chrome.contextMenus?.create({
      id: "pwdsv-manual-save",
      parentId: "pwdsv-root",
      title: "手动提交当前网站密码…",
      contexts: ["page", "editable"],
    });
  });
});

chrome.contextMenus?.onClicked.addListener(async (info, tab) => {
  if (!tab?.id) return;
  if (info.menuItemId === "pwdsv-fill") {
    chrome.tabs.sendMessage(tab.id, { type: "cmd:fill" }).catch(() => {});
  } else if (info.menuItemId === "pwdsv-gen-fill") {
    const pwd = generatePassword({ length: 20, symbols: true });
    chrome.tabs.sendMessage(tab.id, { type: "cmd:fill-generated", password: pwd }).catch(() => {});
  } else if (info.menuItemId === "pwdsv-manual-save") {
    chrome.tabs.sendMessage(tab.id, { type: "cmd:open-save-modal" }).catch(() => {});
  }
});

/* 定时清理过期会话并保活实时同步 */
chrome.alarms?.create("pwdsv-sweep", { periodInMinutes: 1 });
chrome.alarms?.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== "pwdsv-sweep") return;
  const session = await readSession({ touch: false });
  await refreshRealtimeConnection(session);
});
