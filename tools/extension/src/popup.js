/**
 * 浏览器插件弹窗交互逻辑 v2.1：
 * - 解锁（支持 TOTP / 邮箱验证码 / 恢复码等 2FA）
 * - 五态分段检索：当前站 / 🌐通用 / 💻电脑 / 📱手机 / 全部，以及全库实时搜索
 * - 列表悬停快捷操作：无需进详情即可一键「填入」当前网页或一键「复制」密码
 * - 精致详情页：品牌色圆角头像、星标切换、彩色语义密码、强度评估、3+3 动态码 + SVG 倒计时环
 */

import { estimateStrength } from "./lib/generator.js";

const $ = (id) => document.getElementById(id);

const el = {
  lockedView: $("locked-view"),
  vaultView: $("vault-view"),
  detailView: $("detail-view"),
  editorView: $("editor-view"),

  topDomainPill: $("top-domain-pill"),
  btnNew: $("btn-new"),
  btnSync: $("btn-sync"),
  btnLock: $("btn-lock"),
  btnSettings: $("btn-settings"),

  server: $("server"),
  email: $("email"),
  password: $("password"),
  twoFactorField: $("twofactor-field"),
  twoFactorProvider: $("twofactor-provider"),
  twoFactor: $("twofactor"),
  keepSignedIn: $("keep-signed-in"),
  btnSendEmailOtp: $("btn-send-email-otp"),
  unlockForm: $("unlock-form"),
  unlockBtn: $("btn-unlock"),
  unlockError: $("unlock-error"),
  lockedHint: $("locked-hint"),

  search: $("search"),
  tabSite: $("tab-site"),
  tabUni: $("tab-uni"),
  tabApps: $("tab-apps"),
  tabMob: $("tab-mob"),
  tabAll: $("tab-all"),
  list: $("item-list"),
  listEmpty: $("list-empty"),
  emptyText: $("empty-text"),
  btnEmptyNew: $("btn-empty-new"),
  siteHint: $("site-hint"),
  statusText: $("status-text"),
  btnPopupUpdate: $("btn-popup-update"),

  detailAvatar: $("detail-avatar"),
  detailName: $("detail-name"),
  detailFav: $("btn-detail-fav"),
  detailBadges: $("detail-badges"),
  detailUsername: $("detail-username"),
  detailStrength: $("detail-strength"),
  detailPassword: $("detail-password"),
  detailTotpRow: $("detail-totp-row"),
  detailTotp: $("detail-totp"),
  detailTotpCircle: $("detail-totp-circle"),
  totpLeft: $("totp-left"),
  detailUriRow: $("detail-uri-row"),
  detailUris: $("detail-uris"),
  detailNotesRow: $("detail-notes-row"),
  detailNotes: $("detail-notes"),

  editorTitle: $("editor-title"),
  editorForm: $("editor-form"),
  editorError: $("editor-error"),
  edName: $("ed-name"),
  edUsername: $("ed-username"),
  edPassword: $("ed-password"),
  edStrength: $("ed-strength"),
  edScope: $("ed-scope"),
  edUris: $("ed-uris"),
  edTotp: $("ed-totp"),
  edFolder: $("ed-folder"),
  edFavorite: $("ed-favorite"),
  edNotes: $("ed-notes"),
  btnEdSave: $("btn-ed-save"),
};

const state = {
  scope: "site",
  items: [],
  folders: [],
  currentTabUrl: "",
  currentTabTitle: "",
  currentTabId: null,
  selected: null,
  editingId: null,
  revealed: false,
  totpTimer: null,
};

/* ----------------------------------------------------- 视觉排版与密码语义工具 */

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

function applyAvatar(node, name, seed) {
  if (!node) return;
  node.textContent = extractMonogram(name);
  node.style.background = avatarGradientFor(name || seed);
}

function formatTotpSpaced(code) {
  const s = String(code || "").trim();
  if (s.length === 6) return `${s.slice(0, 3)} ${s.slice(3)}`;
  if (s.length === 8) return `${s.slice(0, 4)} ${s.slice(4)}`;
  return s;
}

function renderColoredPassword(container, pwd, revealed) {
  container.textContent = "";
  if (!revealed) {
    container.className = "pwd-val masked";
    container.textContent = "••••••••••••";
    return;
  }
  container.className = "pwd-val";
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

function renderStrengthPill(node, pwd) {
  if (!node) return;
  if (!pwd) {
    node.hidden = true;
    return;
  }
  const { score, label, entropy } = estimateStrength(pwd);
  const cls = score <= 1 ? "strength-weak" : score === 2 ? "strength-mid" : "strength-strong";
  node.hidden = false;
  node.className = `strength-pill ${cls}`;
  node.textContent = `${label} · ${entropy}b`;
}

const SHORT_SCOPE_MAP = {
  universal: "通用",
  web: "网页",
  desktop: "电脑",
  mobile: "手机",
};

/* ------------------------------------------------------------------ 通信 */

function send(msg) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(msg, (res) => {
      const lastError = chrome.runtime.lastError;
      if (lastError) return reject(new Error(lastError.message));
      if (res?.error) return reject(new Error(res.error));
      resolve(res || {});
    });
  });
}

/* ---------------------------------------------------------------- 视图切换 */

function setHeaderUnlocked(unlocked) {
  el.btnNew.hidden = !unlocked;
  el.btnSync.hidden = !unlocked;
  el.btnLock.hidden = !unlocked;
}

function showView(name) {
  el.lockedView.hidden = name !== "locked";
  el.vaultView.hidden = name !== "vault";
  el.detailView.hidden = name !== "detail";
  el.editorView.hidden = name !== "editor";
  setHeaderUnlocked(name !== "locked");
}

function status(text) {
  el.statusText.textContent = text;
}

function safeHost(url) {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:" ? u.hostname : "";
  } catch {
    return "";
  }
}

/* ------------------------------------------------------------------ 解锁 */

function showUnlockError(message) {
  el.unlockError.hidden = !message;
  el.unlockError.textContent = message || "";
}

function populateProviders(providers) {
  el.twoFactorProvider.textContent = "";
  for (const p of providers) {
    const opt = document.createElement("option");
    opt.value = String(p.id);
    opt.textContent = p.emailHint ? `${p.name} (${p.emailHint})` : p.name;
    el.twoFactorProvider.appendChild(opt);
  }
  updateEmailOtpButton();
}

function updateEmailOtpButton() {
  el.btnSendEmailOtp.hidden = Number(el.twoFactorProvider.value) !== 1;
}

el.twoFactorProvider.addEventListener("change", updateEmailOtpButton);

el.btnSendEmailOtp.addEventListener("click", async () => {
  el.btnSendEmailOtp.disabled = true;
  try {
    await send({
      type: "sendEmailOtp",
      serverUrl: el.server.value.trim(),
      email: el.email.value.trim(),
      password: el.password.value,
    });
    status("邮箱验证码已发送，请查收邮件");
  } catch (e) {
    showUnlockError("发送邮件验证码失败：" + e.message);
  } finally {
    el.btnSendEmailOtp.disabled = false;
  }
});

async function doUnlock(event) {
  event?.preventDefault?.();
  showUnlockError("");
  el.unlockBtn.disabled = true;
  const original = el.unlockBtn.textContent;
  el.unlockBtn.textContent = "解锁中…";
  status("正在派生主密钥（Argon2 约需几秒）…");

  try {
    const has2faShown = !el.twoFactorField.hidden;
    const res = await send({
      type: "unlock",
      serverUrl: el.server.value.trim(),
      email: el.email.value.trim(),
      password: el.password.value,
      twoFactorToken: has2faShown ? el.twoFactor.value.trim() || undefined : undefined,
      twoFactorProvider: has2faShown ? Number(el.twoFactorProvider.value || 0) : 0,
      persistSession: el.keepSignedIn ? el.keepSignedIn.checked : true,
    });

    if (res?.needsTwoFactor) {
      populateProviders(res.providers || [{ id: 0, name: "验证器 App" }]);
      el.twoFactorField.hidden = false;
      el.twoFactor.focus();
      status("需要完成两步验证");
      return;
    }

    el.password.value = "";
    el.twoFactor.value = "";
    el.twoFactorField.hidden = true;
    await enterVault();
  } catch (e) {
    showUnlockError(String(e.message || e));
    status("解锁失败");
  } finally {
    el.unlockBtn.disabled = false;
    el.unlockBtn.textContent = original;
  }
}

async function enterVault() {
  if (!safeHost(state.currentTabUrl) && state.scope === "site") {
    state.scope = "all";
  }
  showView("vault");
  await refreshStatus();
  await loadItems();
  checkPopupUpdateSilent();
}

function checkPopupUpdateSilent() {
  send({ type: "checkUpdate" })
    .then((res) => {
      if (!el.btnPopupUpdate) return;
      if (res?.hasUpdate && res.latestVersion) {
        el.btnPopupUpdate.textContent = `⬆ 新版 v${res.latestVersion}`;
        el.btnPopupUpdate.hidden = false;
      } else {
        el.btnPopupUpdate.hidden = true;
      }
    })
    .catch(() => {});
}

async function refreshStatus() {
  const st = await send({ type: "status" });
  if (st.locked) {
    showView("locked");
    el.server.value = st.serverUrl || "";
    el.email.value = st.email || "";
    if (el.keepSignedIn) el.keepSignedIn.checked = st.persistSession !== false;
    status("未解锁");
    return false;
  }
  const when = st.lastSync ? new Date(st.lastSync).toLocaleTimeString("zh-CN", { hour12: false }) : "—";
  status(`${st.email || ""} · 共 ${st.itemCount ?? 0} 条 · 同步于 ${when}`);
  return true;
}

/* ------------------------------------------------------------------ 列表与一键操作 */

const allTabButtons = () => [el.tabSite, el.tabUni, el.tabApps, el.tabMob, el.tabAll].filter(Boolean);

function updateScopeTabs(res, activeScope) {
  el.tabSite.textContent = `当前站 (${res.siteCount ?? 0})`;
  el.tabAll.textContent = `全部 (${res.total ?? 0})`;
  for (const btn of allTabButtons()) {
    btn.classList.toggle("active", btn.dataset.scope === activeScope);
  }
}

async function quickFillById(id) {
  if (!state.currentTabId) return;
  const res = await send({ type: "fillData", id, force: true });
  try {
    await chrome.tabs.sendMessage(state.currentTabId, {
      type: "cmd:fill-direct",
      username: res.username,
      password: res.password,
      totp: res.totp || "",
    });
    status(`✓ 已填入「${res.name || "账号"}」到当前页面`);
  } catch {
    status("当前标签页不支持网页表单注入（可直接复制密码）");
  }
}

async function quickCopyById(id, field = "password", label = "密码") {
  const res = await send({ type: "secret", id, field });
  if (!res.value) return;
  await navigator.clipboard.writeText(res.value);
  status(`✓ 已安全复制${label}（30 秒后自动清空）`);
  setTimeout(() => {
    navigator.clipboard.writeText("").catch(() => {});
  }, 30000);
}

function renderItems(items) {
  el.list.textContent = "";
  el.listEmpty.hidden = items.length > 0;
  const canFillWeb = Boolean(safeHost(state.currentTabUrl));

  for (const item of items) {
    const li = document.createElement("li");
    li.addEventListener("click", () => openDetail(item.id));

    const avatar = document.createElement("div");
    avatar.className = "p-avatar";
    applyAvatar(avatar, item.name || item.username, item.id);

    const meta = document.createElement("div");
    meta.className = "meta";

    const name = document.createElement("div");
    name.className = "name";
    name.textContent = (item.favorite ? "★ " : "") + (item.name || "(未命名)");

    const user = document.createElement("div");
    user.className = "user";
    user.textContent = item.username || item.folderName || (item.uris?.[0]?.uri ?? "—");

    meta.append(name, user);

    const tags = document.createElement("div");
    tags.className = "row-tags";
    const sc = item.pwdsvScope || "universal";
    const scTag = document.createElement("span");
    scTag.className = `tag ${sc}`;
    scTag.textContent = SHORT_SCOPE_MAP[sc] || "通用";
    tags.appendChild(scTag);

    if (item.hasTotp) {
      const tTag = document.createElement("span");
      tTag.className = "tag totp-tag";
      tTag.textContent = "2FA";
      tags.appendChild(tTag);
    }

    const ops = document.createElement("div");
    ops.className = "row-ops";
    if (canFillWeb && !item.isApp) {
      const btnFill = document.createElement("button");
      btnFill.type = "button";
      btnFill.className = "op-pill fill";
      btnFill.textContent = "填入";
      btnFill.title = "一键填入当前网页";
      btnFill.addEventListener("click", (ev) => {
        ev.stopPropagation();
        quickFillById(item.id);
      });
      ops.appendChild(btnFill);
    }
    const btnCopy = document.createElement("button");
    btnCopy.type = "button";
    btnCopy.className = "op-pill";
    btnCopy.textContent = "复制";
    btnCopy.title = "一键复制密码";
    btnCopy.addEventListener("click", (ev) => {
      ev.stopPropagation();
      quickCopyById(item.id, "password", `「${item.name}」密码`);
    });
    ops.appendChild(btnCopy);

    li.append(avatar, meta, tags, ops);
    el.list.appendChild(li);
  }
}

async function loadItems() {
  const query = el.search.value.trim();
  const effectiveScope = query ? "all" : state.scope;
  const res = await send({
    type: "list",
    query,
    scope: effectiveScope,
    url: state.currentTabUrl,
  });
  if (res.locked) {
    await refreshStatus();
    return;
  }

  state.items = res.items || [];
  state.folders = res.folders || [];
  updateScopeTabs(res, effectiveScope);

  const host = safeHost(state.currentTabUrl);
  if (host && effectiveScope === "site" && !query) {
    el.siteHint.hidden = false;
    el.siteHint.textContent = `🌐 当前站点 ${host} · 匹配到 ${res.siteCount} 条可用账号`;
    el.emptyText.textContent = `尚未保存 ${host} 的登录密码`;
  } else {
    el.siteHint.hidden = true;
    el.emptyText.textContent = query ? "没有搜到匹配的密码记录" : "当前筛选分类下暂无记录";
  }

  renderItems(state.items);
}

for (const btn of allTabButtons()) {
  btn.addEventListener("click", () => {
    state.scope = btn.dataset.scope;
    el.search.value = "";
    loadItems();
  });
}

/* ------------------------------------------------------------------ 详情 */

function uriPlatformIcon(uri) {
  const u = String(uri || "");
  if (/^app:\/\//i.test(u)) return "💻";
  if (/^androidapp:\/\//i.test(u)) return "📱";
  return "🌐";
}

async function openDetail(id) {
  const { item } = await send({ type: "getItem", id });
  state.selected = item;
  state.revealed = false;
  $("btn-reveal").textContent = "显示";
  showView("detail");

  applyAvatar(el.detailAvatar, item.name || item.username, item.id);
  el.detailName.textContent = item.name || "(未命名)";
  if (el.detailFav) {
    el.detailFav.textContent = item.favorite ? "★" : "☆";
    el.detailFav.style.opacity = item.favorite ? "1" : "0.45";
  }

  el.detailBadges.textContent = "";
  const sc = item.pwdsvScope || "universal";
  if (item.scopeLabel) {
    const b = document.createElement("span");
    b.className = `tag ${sc}`;
    b.textContent = item.scopeLabel;
    el.detailBadges.appendChild(b);
  }
  if (item.folderName) {
    const f = document.createElement("span");
    f.className = "tag";
    f.textContent = "📁 " + item.folderName;
    el.detailBadges.appendChild(f);
  }
  if (item.passwordHistoryCount > 0) {
    const h = document.createElement("span");
    h.className = "tag";
    h.textContent = `历史 ${item.passwordHistoryCount} 条`;
    el.detailBadges.appendChild(h);
  }

  el.detailUsername.textContent = item.username || "—";
  renderStrengthPill(el.detailStrength, item.password);
  renderColoredPassword(el.detailPassword, item.password, false);

  el.detailUriRow.hidden = !item.uris?.length;
  el.detailUris.textContent = "";
  for (const u of item.uris || []) {
    const chip = document.createElement("div");
    chip.className = "uri-chip";
    const ic = document.createElement("span");
    ic.textContent = uriPlatformIcon(u.uri);
    const sp = document.createElement("span");
    sp.textContent = u.uri;
    chip.append(ic, sp);
    el.detailUris.appendChild(chip);
  }

  el.detailNotesRow.hidden = !item.notes;
  el.detailNotes.textContent = item.notes || "";

  el.detailTotpRow.hidden = !item.totp;
  if (item.totp) startTotpLoop();
  else stopTotpLoop();
}

el.detailFav?.addEventListener("click", async () => {
  const item = state.selected;
  if (!item) return;
  try {
    const nextFav = !item.favorite;
    await send({
      type: "save",
      id: item.id,
      name: item.name,
      username: item.username,
      password: item.password,
      pwdsvScope: item.pwdsvScope || "universal",
      uris: item.uris || [],
      totp: item.totp || "",
      folderId: item.folderId || null,
      favorite: nextFav,
      notes: item.notes || "",
    });
    await openDetail(item.id);
    status(nextFav ? "★ 已设为星标收藏" : "已取消星标收藏");
  } catch (e) {
    status("更新收藏失败：" + e.message);
  }
});

function reveal() {
  if (!state.selected) return;
  state.revealed = !state.revealed;
  renderColoredPassword(el.detailPassword, state.selected.password, state.revealed);
  $("btn-reveal").textContent = state.revealed ? "隐藏" : "显示";
}

async function copyField(field) {
  if (!state.selected) return;
  const labels = { username: "账号", password: "密码", totp: "验证码" };
  await quickCopyById(state.selected.id, field, labels[field] || "内容");
}

function startTotpLoop() {
  stopTotpLoop();
  const circumference = 56.55;
  const tick = async () => {
    if (!state.selected) return;
    try {
      const res = await send({ type: "secret", id: state.selected.id, field: "totp" });
      el.detailTotp.textContent = formatTotpSpaced(res.value || "—");
      el.totpLeft.textContent = res.remaining ? `${res.remaining}s` : "";
      if (el.detailTotpCircle && res.remaining) {
        const total = res.period || 30;
        const offset = circumference * (1 - res.remaining / total);
        el.detailTotpCircle.setAttribute("stroke-dashoffset", offset.toFixed(2));
        el.detailTotpCircle.style.stroke = res.remaining <= 5 ? "#f59e0b" : "#34d399";
      }
    } catch {
      el.detailTotp.textContent = "密钥格式有误";
      el.totpLeft.textContent = "";
    }
  };
  tick();
  state.totpTimer = setInterval(tick, 1000);
}

function stopTotpLoop() {
  if (state.totpTimer) clearInterval(state.totpTimer);
  state.totpTimer = null;
  el.detailTotp.textContent = "";
  el.totpLeft.textContent = "";
}

async function deleteSelected() {
  if (!state.selected) return;
  if (!confirm(`确定要从服务器永久删除「${state.selected.name}」吗？`)) return;
  try {
    status("正在删除…");
    await send({ type: "deleteCipher", id: state.selected.id });
    stopTotpLoop();
    state.selected = null;
    await enterVault();
    status("已删除该记录");
  } catch (e) {
    status("删除失败：" + e.message);
  }
}

/* -------------------------------------------------------- 新建 / 编辑表单 */

function populateFolderSelect(selectedId = "") {
  el.edFolder.textContent = "";
  const none = document.createElement("option");
  none.value = "";
  none.textContent = "无文件夹";
  el.edFolder.appendChild(none);
  for (const f of state.folders || []) {
    const opt = document.createElement("option");
    opt.value = f.id;
    opt.textContent = f.name || "未命名文件夹";
    el.edFolder.appendChild(opt);
  }
  el.edFolder.value = selectedId || "";
}

function openEditor(item = null) {
  stopTotpLoop();
  el.editorError.hidden = true;
  el.edPassword.type = "password";
  $("btn-ed-eye").textContent = "显示";
  populateFolderSelect(item?.folderId || "");

  if (item) {
    state.editingId = item.id;
    el.editorTitle.textContent = "编辑密码";
    el.edName.value = item.name || "";
    el.edUsername.value = item.username || "";
    el.edPassword.value = item.password || "";
    el.edScope.value = item.pwdsvScope || "universal";
    el.edUris.value = (item.uris || []).map((u) => u.uri).join("\n");
    el.edTotp.value = item.totp || "";
    el.edFavorite.checked = Boolean(item.favorite);
    el.edNotes.value = item.notes || "";
  } else {
    state.editingId = null;
    el.editorTitle.textContent = "提交新密码";
    const host = safeHost(state.currentTabUrl);
    el.edName.value = host ? state.currentTabTitle?.slice(0, 36) || host : "";
    el.edUsername.value = "";
    el.edPassword.value = "";
    el.edScope.value =
      state.scope === "apps" ? "desktop" : state.scope === "mobile" ? "mobile" : "universal";
    el.edUris.value = host
      ? state.currentTabUrl
      : state.scope === "apps"
        ? "app://"
        : state.scope === "mobile"
          ? "androidapp://"
          : "";
    el.edTotp.value = "";
    el.edFavorite.checked = false;
    el.edNotes.value = "";
  }

  renderStrengthPill(el.edStrength, el.edPassword.value);
  showView("editor");
  (el.edName.value ? el.edUsername : el.edName).focus();
}

el.edPassword.addEventListener("input", () => {
  renderStrengthPill(el.edStrength, el.edPassword.value);
});

$("btn-ed-eye").addEventListener("click", () => {
  const hidden = el.edPassword.type === "password";
  el.edPassword.type = hidden ? "text" : "password";
  $("btn-ed-eye").textContent = hidden ? "隐藏" : "显示";
});

$("btn-ed-gen").addEventListener("click", async () => {
  const res = await send({ type: "generate", kind: "password", length: 20, symbols: true });
  el.edPassword.value = res.value;
  el.edPassword.type = "text";
  $("btn-ed-eye").textContent = "隐藏";
  renderStrengthPill(el.edStrength, el.edPassword.value);
});

el.editorForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  el.editorError.hidden = true;
  el.btnEdSave.disabled = true;
  const orig = el.btnEdSave.textContent;
  el.btnEdSave.textContent = "加密提交中…";

  try {
    const uris = el.edUris.value
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map((uri) => ({ uri, match: null }));

    const res = await send({
      type: "save",
      id: state.editingId,
      name: el.edName.value.trim(),
      username: el.edUsername.value.trim(),
      password: el.edPassword.value,
      pwdsvScope: el.edScope.value || "universal",
      uris,
      totp: el.edTotp.value.trim(),
      folderId: el.edFolder.value || null,
      favorite: el.edFavorite.checked,
      notes: el.edNotes.value.trim(),
    });

    await refreshStatus();
    await loadItems();
    if (res.id) {
      await openDetail(res.id);
    } else {
      showView("vault");
    }
    status(state.editingId ? "已保存修改并同步" : "新密码已提交入库");
  } catch (err) {
    el.editorError.hidden = false;
    el.editorError.textContent = String(err.message || err);
  } finally {
    el.btnEdSave.disabled = false;
    el.btnEdSave.textContent = orig;
  }
});

/* ------------------------------------------------------------------ 填充与生成 */

async function fillCurrentPage() {
  if (!state.selected) return;
  await quickFillById(state.selected.id);
}

async function generatePasswordInPopup() {
  const res = await send({ type: "generate", kind: "password", length: 20, symbols: true });
  $("gen-value").textContent = res.value;
  $("gen-result").hidden = false;
  $("btn-gen-copy").hidden = false;
}

/* ------------------------------------------------------------------ 入口 */

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  state.currentTabId = tab?.id ?? null;
  state.currentTabUrl = tab?.url || "";
  state.currentTabTitle = tab?.title || "";

  const host = safeHost(state.currentTabUrl);
  if (el.topDomainPill) {
    el.topDomainPill.textContent = host ? `当前网页：${host}` : "零知识加密助手";
  }

  try {
    const st = await send({ type: "status" });
    if (st.locked) {
      showView("locked");
      el.server.value = st.serverUrl || "";
      el.email.value = st.email || "";
      if (el.keepSignedIn) el.keepSignedIn.checked = st.persistSession !== false;
      if (!st.serverUrl) el.lockedHint.textContent = "首次使用请先填写 PWDSV 服务器地址（如 https://你的域名）。";
      status("未解锁");
      (st.serverUrl ? el.password : el.server).focus();
    } else {
      await enterVault();
    }
  } catch (e) {
    showView("locked");
    showUnlockError("后台服务未响应：" + e.message);
  }
}

el.unlockForm.addEventListener("submit", doUnlock);
el.search.addEventListener("input", loadItems);
el.btnNew.addEventListener("click", () => openEditor(null));
el.btnEmptyNew.addEventListener("click", () => openEditor(null));

$("btn-back").addEventListener("click", () => {
  stopTotpLoop();
  showView("vault");
});
$("btn-edit").addEventListener("click", () => {
  if (state.selected) openEditor(state.selected);
});
$("btn-delete").addEventListener("click", deleteSelected);
$("btn-editor-cancel").addEventListener("click", () => {
  if (state.selected && state.editingId) openDetail(state.selected.id);
  else showView("vault");
});

$("btn-reveal").addEventListener("click", reveal);
$("btn-fill").addEventListener("click", fillCurrentPage);
$("btn-generate").addEventListener("click", generatePasswordInPopup);
$("btn-gen-copy").addEventListener("click", async () => {
  const value = $("gen-value").textContent;
  if (value) {
    await navigator.clipboard.writeText(value);
    status("✓ 随机强密码已复制");
  }
});
document.querySelectorAll("[data-copy]").forEach((btn) => {
  btn.addEventListener("click", () => copyField(btn.dataset.copy));
});
el.btnLock.addEventListener("click", async () => {
  await send({ type: "lock" });
  stopTotpLoop();
  showView("locked");
  status("已锁定");
  await refreshStatus();
});
el.btnSync.addEventListener("click", async () => {
  status("同步中…");
  try {
    const res = await send({ type: "sync" });
    if (state.selected) stopTotpLoop();
    await enterVault();
    status("同步完成，共 " + res.itemCount + " 条");
  } catch (e) {
    status("同步失败：" + e.message);
  }
});
el.btnSettings.addEventListener("click", () => chrome.runtime.openOptionsPage());
el.btnPopupUpdate?.addEventListener("click", () => chrome.runtime.openOptionsPage());

init();
