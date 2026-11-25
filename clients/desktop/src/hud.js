/**
 * 无抢焦点悬浮提示卡（HUD）：
 * 当用户打开绑定的桌面应用（或按下 Ctrl+Alt+P）时，在屏幕右上角静默浮现，
 * 原软件密码框焦点不受影响，点「键入密码」直接通过 Win32 SendInput 输入到目标窗口。
 */

const tauriCore = window.__TAURI__?.core;
const tauriEvent = window.__TAURI__?.event;
const invoke = (cmd, args) => tauriCore.invoke(cmd, args);

const $ = (id) => document.getElementById(id);
const el = {
  card: $("hud-card"),
  exe: $("hud-exe"),
  matched: $("hud-matched"),
  unmatched: $("hud-unmatched"),
  unmatchedText: $("hud-unmatched-text"),
  select: $("hud-select"),
  totp: $("hud-totp"),
  userHint: $("hud-user-hint"),
  progress: $("hud-progress"),
};

const AUTO_HIDE_MS = 10000;
let currentPayload = null;
let countdownTimer = null;
let remainingMs = AUTO_HIDE_MS;
let hovered = false;

el.card.addEventListener("mouseenter", () => { hovered = true; });
el.card.addEventListener("mouseleave", () => { hovered = false; });

function selectedCandidate() {
  if (!currentPayload?.candidates?.length) return null;
  const id = el.select.value;
  return currentPayload.candidates.find((c) => c.id === id) || currentPayload.candidates[0];
}

function formatTotpDisplay(code) {
  const s = String(code || "").trim();
  if (s.length === 6) return `${s.slice(0, 3)} ${s.slice(3)}`;
  if (s.length === 8) return `${s.slice(0, 4)} ${s.slice(4)}`;
  return s;
}

function syncCandidateDetail() {
  const c = selectedCandidate();
  if (!c) return;
  el.userHint.textContent = c.username
    ? `账号：${c.username}`
    : (currentPayload.title ? `窗口：${currentPayload.title}` : "未填写用户名，可直接键入密码");

  if (c.totpCode) {
    el.totp.hidden = false;
    el.totp.textContent = `动态码 ${formatTotpDisplay(c.totpCode)}`;
  } else {
    el.totp.hidden = true;
  }
}

function startCountdown() {
  if (countdownTimer) clearInterval(countdownTimer);
  remainingMs = AUTO_HIDE_MS;
  el.progress.style.width = "100%";

  countdownTimer = setInterval(() => {
    if (hovered) return;
    remainingMs -= 200;
    const pct = Math.max(0, (remainingMs / AUTO_HIDE_MS) * 100);
    el.progress.style.width = pct + "%";
    if (remainingMs <= 0) {
      clearInterval(countdownTimer);
      countdownTimer = null;
      invoke("hide_hud_window").catch(() => {});
    }
  }, 200);
}

function renderPayload(payload) {
  if (!payload) return;
  currentPayload = payload;
  el.exe.textContent = payload.exe || "应用";

  const hasMatches = Array.isArray(payload.candidates) && payload.candidates.length > 0;
  el.matched.hidden = !hasMatches;
  el.unmatched.hidden = hasMatches;

  if (hasMatches) {
    el.select.textContent = "";
    for (const item of payload.candidates) {
      const opt = document.createElement("option");
      opt.value = item.id;
      opt.textContent = item.username ? `${item.name} (${item.username})` : item.name;
      el.select.appendChild(opt);
    }
    syncCandidateDetail();
  } else {
    el.unmatchedText.textContent = payload.locked
      ? `检测到 ${payload.exe}，请先解锁 PWDSV 密码库`
      : `当前前台程序 ${payload.exe} 尚未绑定密码`;
    $("btn-hud-add-app").textContent = payload.locked ? "打开密码库解锁" : "＋ 为此程序提交密码";
  }

  startCountdown();
}

async function sendHudAction(action, extra = {}) {
  const cand = selectedCandidate();
  await invoke("dispatch_hud_action", {
    action: {
      kind: action,
      itemId: cand?.id || null,
      hwnd: currentPayload?.hwnd || 0,
      pid: currentPayload?.pid || 0,
      exe: currentPayload?.exe || "",
      title: currentPayload?.title || "",
      ...extra,
    },
  });
}

el.select.addEventListener("change", syncCandidateDetail);
$("btn-hud-close").addEventListener("click", () => invoke("hide_hud_window"));
$("btn-hud-dismiss").addEventListener("click", () => invoke("hide_hud_window"));

$("btn-hud-type-pwd").addEventListener("click", () => sendHudAction("autotype-pwd"));
$("btn-hud-type-both").addEventListener("click", () => sendHudAction("autotype-both"));
$("btn-hud-copy").addEventListener("click", () => sendHudAction("copy-pwd"));
$("btn-hud-mute").addEventListener("click", () => sendHudAction("mute-pid"));
$("btn-hud-add-app").addEventListener("click", () => sendHudAction("add-for-app"));
el.totp.addEventListener("click", () => sendHudAction("copy-totp"));

tauriEvent?.listen("pwdsv://hud-render", (event) => {
  renderPayload(event.payload);
});

invoke("get_hud_payload").then((p) => {
  if (p) renderPayload(p);
}).catch(() => {});
