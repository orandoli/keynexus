/** 设置页：读写 chrome.storage.local、管理免打扰域名，顺手测服务器连通性 */

const $ = (id) => document.getElementById(id);

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

let currentNeverSave = [];
let pendingDownloadUrl = "";

function renderNeverSave(domains) {
  currentNeverSave = Array.isArray(domains) ? [...domains] : [];
  const list = $("never-save-list");
  const empty = $("never-save-empty");
  list.textContent = "";
  empty.hidden = currentNeverSave.length > 0;

  for (const host of currentNeverSave) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ghost";
    btn.textContent = host + "  ×";
    btn.title = "点击恢复此网站的保存提示";
    btn.addEventListener("click", async () => {
      const next = currentNeverSave.filter((h) => h !== host);
      const updated = await send({ type: "settings", patch: { neverSaveDomains: next } });
      renderNeverSave(updated.neverSaveDomains);
    });
    list.appendChild(btn);
  }
}

async function load() {
  const settings = await send({ type: "settings" });
  $("server").value = settings.serverUrl || "";
  $("email").value = settings.email || "";
  $("lockMinutes").value = settings.lockMinutes ?? 15;
  $("loginToast").checked = settings.loginToast !== false;
  $("autofillOnLoad").checked = Boolean(settings.autofillOnLoad);
  $("savePrompt").checked = settings.savePrompt !== false;
  $("otpAutofill").checked = settings.otpAutofill !== false;
  $("strictHost").checked = Boolean(settings.strictHost);
  $("realtimeSync").checked = settings.realtimeSync !== false;
  if ($("updateManifestUrl")) $("updateManifestUrl").value = settings.updateManifestUrl || "";
  renderNeverSave(settings.neverSaveDomains);
  const ver = chrome.runtime.getManifest().version;
  $("version").textContent = "版本 " + ver;
  if ($("ext-cur-ver")) $("ext-cur-ver").textContent = "· 当前 v" + ver;
}

async function save() {
  const patch = {
    serverUrl: ($("server").value || "").trim(),
    email: ($("email").value || "").trim(),
    lockMinutes: Math.max(0, Math.min(1440, Number($("lockMinutes").value) || 0)),
    loginToast: $("loginToast").checked,
    autofillOnLoad: $("autofillOnLoad").checked,
    savePrompt: $("savePrompt").checked,
    otpAutofill: $("otpAutofill").checked,
    strictHost: $("strictHost").checked,
    realtimeSync: $("realtimeSync").checked,
    updateManifestUrl: ($("updateManifestUrl")?.value || "").trim(),
  };
  await send({ type: "settings", patch });
}

for (const id of [
  "server",
  "email",
  "lockMinutes",
  "loginToast",
  "autofillOnLoad",
  "savePrompt",
  "otpAutofill",
  "strictHost",
  "realtimeSync",
  "updateManifestUrl",
]) {
  $(id)?.addEventListener("change", save);
}

$("btn-ping").addEventListener("click", async () => {
  const out = $("ping-result");
  out.textContent = "连接中…";
  try {
    await save();
    const res = await send({ type: "ping", serverUrl: $("server").value.trim() });
    out.textContent = "连通成功，服务端版本 " + (res.version || "正常");
  } catch (e) {
    out.textContent = "连接失败：" + e.message;
  }
});

$("btn-clear").addEventListener("click", async () => {
  const out = $("clear-result");
  await send({ type: "logout" });
  await load();
  out.textContent = "已清空并锁定，回弹窗可重新登录";
});

$("btn-check-update")?.addEventListener("click", async () => {
  const out = $("update-status");
  const dlBtn = $("btn-download-update");
  out.textContent = "检查中…";
  dlBtn.hidden = true;
  pendingDownloadUrl = "";
  try {
    await save();
    const res = await send({
      type: "checkUpdate",
      serverUrl: $("server").value.trim(),
      customManifestUrl: $("updateManifestUrl")?.value.trim() || "",
    });
    if (res.hasUpdate && res.downloadUrl) {
      pendingDownloadUrl = res.downloadUrl;
      dlBtn.textContent = `⬇ 下载新版 v${res.latestVersion}`;
      dlBtn.hidden = false;
      out.textContent = `发现新版 v${res.latestVersion}${res.notes ? `（${res.notes}）` : ""}`;
    } else {
      out.textContent = `当前 v${res.currentVersion} 已是最新版本`;
    }
  } catch (e) {
    out.textContent = "检查更新失败：" + e.message;
  }
});

$("btn-download-update")?.addEventListener("click", () => {
  if (pendingDownloadUrl) chrome.tabs.create({ url: pendingDownloadUrl });
});

$("btn-open-extensions")?.addEventListener("click", () => {
  chrome.tabs.create({ url: "chrome://extensions/" });
});

load();
