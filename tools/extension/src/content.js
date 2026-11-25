/**
 * 内容脚本 v2.0：
 * 1. 下次登录提示：检测登录框并在输入框右侧显示 PWDSV 钥匙角标 + 右上角一键登录轻胶囊（支持动态 SPA 弹窗与同源 iframe）
 * 2. 访问网站记密码：支持普通登录、两步登录（先账号后密码）、修改密码，提交前同步暂存到后台，跳转新页面后依然弹出「保存/更新」卡片
 * 3. 手动提交密码：右键菜单或保存卡片里直接编辑标题、账号、密码并入库
 * 4. TOTP 自动接力：聚焦或新弹出验证码输入框时自动填入当前 6 位动态码
 */

(function () {
  "use strict";
  if (window.__pwdsvInjected) return;
  window.__pwdsvInjected = true;

  const isTopFrame = window === window.top;

  const OTP_SELECTORS = [
    'input[autocomplete="one-time-code"]',
    'input[name*="totp" i]', 'input[name*="otp" i]', 'input[name*="mfa" i]',
    'input[name*="2fa" i]', 'input[name*="verification" i]', 'input[name*="passcode" i]',
    'input[name*="auth_code" i]', 'input[name*="security_code" i]', 'input[name*="two_factor" i]',
    'input[id*="otp" i]', 'input[id*="totp" i]', 'input[id*="2fa" i]',
    'input[id*="two-factor" i]', 'input[id*="mfa" i]',
    'input[placeholder*="验证码"]', 'input[placeholder*="安全码"]', 'input[placeholder*="动态口令"]',
    'input[placeholder*="verification" i]', 'input[placeholder*="one-time" i]',
    'input[placeholder*="6-digit" i]', 'input[placeholder*="auth code" i]',
    'input[aria-label*="verification" i]', 'input[aria-label*="one-time" i]',
    'input[data-testid*="otp" i]', 'input[data-testid*="totp" i]',
    'input[inputmode="numeric"][maxlength="6"]',
  ];

  let settings = { autofillOnLoad: false, loginToast: true, savePrompt: true, otpAutofill: true };
  let candidates = [];
  let shadow = null;
  let badgeBtn = null;
  let panel = null;
  let toast = null;
  let banner = null;

  let activeInput = null;
  let badgeTarget = null;
  let toastShownThisPage = false;
  let lastKnownUrl = location.href;
  const otpFilledFor = new WeakSet();

  /* ---------------------------------------------------------------- 小工具 */

  function send(msg) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(msg, (res) => {
          void chrome.runtime.lastError;
          resolve(res || {});
        });
      } catch {
        resolve({ error: "extension-context-lost" });
      }
    });
  }

  function visible(el) {
    if (!el || el.disabled || el.readOnly || el.type === "hidden") return false;
    const rect = el.getBoundingClientRect();
    if (rect.width < 24 || rect.height < 14) return false;
    const style = getComputedStyle(el);
    return style.visibility !== "hidden" && style.display !== "none" && Number(style.opacity) > 0.05;
  }

  function isSearchLike(el) {
    if (!el) return false;
    if (el.type === "search") return true;
    const role = (el.getAttribute("role") || "").toLowerCase();
    if (role === "searchbox" || role === "combobox") return true;
    const hint = [el.name, el.id, el.placeholder, el.getAttribute("aria-label")].join(" ").toLowerCase();
    return /\b(search|query|keyword|q)\b|搜索|查找|检索/.test(hint) && !/user|mail|login|账号|邮箱/.test(hint);
  }

  function isOtpInput(el) {
    if (!el || el.tagName !== "INPUT") return false;
    return OTP_SELECTORS.some((sel) => {
      try {
        return el.matches(sel);
      } catch {
        return false;
      }
    });
  }

  function passwordFields(root = document) {
    return Array.from(root.querySelectorAll('input[type="password"]')).filter(visible);
  }

  function textFieldsNear(input) {
    const scope = input?.form || document;
    return Array.from(
      scope.querySelectorAll('input[type="text"], input[type="email"], input[type="tel"], input:not([type])'),
    ).filter((el) => visible(el) && el !== input && !isSearchLike(el) && !isOtpInput(el));
  }

  function looksLikeUsernameField(el) {
    if (!el || el.tagName !== "INPUT" || isSearchLike(el) || isOtpInput(el)) return false;
    if (!["text", "email", "tel", ""].includes(el.type || "")) return false;
    const auto = (el.autocomplete || "").toLowerCase();
    if (auto.includes("username") || auto.includes("email")) return true;
    const hint = [el.name, el.id, el.placeholder, el.getAttribute("aria-label")].join(" ").toLowerCase();
    if (/user|login|e-?mail|account|phone|mobile|member|账号|账户|邮箱|手机|用户名|工号|学号/.test(hint)) return true;
    if (el.form && el.form.querySelector('input[type="password"]')) return true;
    return false;
  }

  function looksLikeLoginField(el) {
    if (!el || el.tagName !== "INPUT") return false;
    if (el.type === "password") return true;
    return looksLikeUsernameField(el);
  }

  function guessUsernameField(passwordInput) {
    const scope = passwordInput?.form || document;
    const all = Array.from(scope.querySelectorAll("input")).filter(visible);
    const idx = all.indexOf(passwordInput);
    for (let i = (idx >= 0 ? idx - 1 : all.length - 1); i >= 0; i--) {
      const el = all[i];
      if (el.type === "password" || el.type === "hidden" || isSearchLike(el) || isOtpInput(el)) continue;
      if (["email", "text", "tel", ""].includes(el.type || "")) return el;
    }
    const named = scope.querySelector(
      'input[autocomplete*="username" i], input[name*="user" i], input[name*="email" i], input[id*="user" i], input[id*="email" i]',
    );
    if (named && visible(named)) return named;
    return textFieldsNear(passwordInput)[0] || null;
  }

  /**
   * 区分「登录密码」与「修改密码页的新密码」：
   * 若存在 autocomplete="new-password"，优先取新密码；若有 2~3 个密码框（旧密码+新密码+确认密码），取新密码框。
   */
  function pickTargetPasswordForSave(pwds) {
    const filled = pwds.filter((p) => Boolean(p.value));
    if (!filled.length) return null;
    const explicitNew = filled.find((p) => (p.autocomplete || "").toLowerCase().includes("new-password"));
    if (explicitNew) return explicitNew;
    if (filled.length >= 2) {
      // 若后两个值相同（新密码 + 确认新密码），取其中之一；否则取最后一个非空密码框
      const last = filled[filled.length - 1];
      const prev = filled[filled.length - 2];
      if (last.value === prev.value) return prev;
      return last;
    }
    return filled[0];
  }

  function setValue(el, value) {
    if (!el) return;
    const proto = Object.getPrototypeOf(el);
    const desc = Object.getOwnPropertyDescriptor(proto, "value");
    el.focus();
    if (desc && desc.set) desc.set.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    el.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true, key: "Unidentified" }));
  }

  function fillCredentials(item) {
    const pwds = passwordFields();
    const pwd = pwds[0] || null;
    const user = pwd ? guessUsernameField(pwd) : Array.from(document.querySelectorAll("input")).find((el) => visible(el) && looksLikeUsernameField(el));

    let touched = false;
    if (user && item.username) {
      setValue(user, item.username);
      touched = true;
    }
    if (pwd && item.password) {
      setValue(pwd, item.password);
      touched = true;
      // 注册页双密码框但没有 current-password 时，顺手填确认密码框
      if (pwds.length === 2 && !(pwds[0].autocomplete || "").includes("current")) {
        setValue(pwds[1], item.password);
      }
    }
    // 同屏如果有验证码框且条目带 TOTP，一并填进去
    if (item.totp) {
      const otpEl = Array.from(document.querySelectorAll("input")).find((el) => visible(el) && isOtpInput(el));
      if (otpEl && !otpEl.value) setValue(otpEl, item.totp);
    }
    return touched;
  }

  /* ----------------------------------------------------------- Shadow DOM UI */

  function ensureShadow() {
    if (shadow) return shadow;
    const host = document.createElement("div");
    host.id = "pwdsv-root";
    host.style.cssText = "all:initial;position:fixed;inset:0;pointer-events:none;z-index:2147483646;";
    document.documentElement.appendChild(host);
    shadow = host.attachShadow({ mode: "open" });

    const style = document.createElement("style");
    style.textContent = STYLES;
    shadow.appendChild(style);

    badgeBtn = document.createElement("button");
    badgeBtn.className = "key-badge";
    badgeBtn.type = "button";
    badgeBtn.title = "点击使用 KeyNexus 自动填充";
    badgeBtn.style.display = "none";
    badgeBtn.addEventListener("mousedown", (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (badgeTarget) {
        activeInput = badgeTarget;
        if (panel.style.display === "block") hidePanel();
        else showPanel(badgeTarget, candidates);
      }
    });
    shadow.appendChild(badgeBtn);

    panel = document.createElement("div");
    panel.className = "panel";
    panel.style.display = "none";
    shadow.appendChild(panel);

    toast = document.createElement("div");
    toast.className = "login-toast";
    toast.style.display = "none";
    shadow.appendChild(toast);

    banner = document.createElement("div");
    banner.className = "banner";
    banner.style.display = "none";
    shadow.appendChild(banner);

    return shadow;
  }

  const STYLES = [
    ":host{all:initial}",
    ".key-badge{position:fixed;pointer-events:auto;display:inline-flex;align-items:center;gap:3px;height:22px;padding:0 6px;",
    "  border-radius:6px;border:1px solid #1d6fb8;background:#0f2236;color:#cfe6ff;cursor:pointer;",
    "  font:600 11px/1 system-ui,-apple-system,'Segoe UI','Microsoft YaHei',sans-serif;box-shadow:0 2px 8px rgba(0,0,0,.28)}",
    ".key-badge:hover{background:#145896;color:#fff}",
    ".panel{position:fixed;pointer-events:auto;min-width:268px;max-width:350px;background:#16212d;",
    "  color:#e8eef5;border:1px solid #2a3b4d;border-radius:10px;box-shadow:0 12px 32px rgba(0,0,0,.45);",
    "  font:13px/1.45 system-ui,-apple-system,'Segoe UI','Microsoft YaHei',sans-serif;overflow:hidden}",
    ".panel header{display:flex;align-items:center;justify-content:space-between;padding:8px 10px;background:#0f1720;",
    "  border-bottom:1px solid #2a3b4d;font-size:11px;color:#8aa2b8}",
    ".panel header b{color:#4aa3f0;font-weight:700;letter-spacing:.04em}",
    ".panel .link-btn{border:0;background:transparent;color:#66b3ff;font:inherit;cursor:pointer;padding:2px 4px}",
    ".row{display:flex;align-items:center;gap:8px;padding:9px 10px;cursor:pointer;border:0;width:100%;",
    "  background:transparent;color:inherit;text-align:left;font:inherit}",
    ".row:hover{background:#1f2e3d}",
    ".row .name{font-weight:600;color:#f2f7fc}",
    ".row .user{color:#8aa2b8;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
    ".badge{margin-left:auto;background:#0b4f8a;color:#cfe6ff;border-radius:999px;padding:1px 7px;font-size:10px}",
    ".empty{padding:12px 10px;color:#8aa2b8;font-size:12px}",
    ".login-toast{position:fixed;pointer-events:auto;top:16px;right:16px;display:flex;align-items:center;gap:10px;",
    "  max-width:360px;background:#13202e;color:#e8eef5;border:1px solid #284b6e;border-radius:999px;",
    "  padding:7px 10px 7px 14px;box-shadow:0 10px 28px rgba(0,0,0,.42);",
    "  font:12px/1.4 system-ui,-apple-system,'Segoe UI','Microsoft YaHei',sans-serif}",
    ".login-toast .txt{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
    ".login-toast b{color:#6ec1ff}",
    ".login-toast button{border-radius:999px;border:1px solid #2a3b4d;background:#1d2e40;color:#e8eef5;padding:4px 10px;font:inherit;cursor:pointer}",
    ".login-toast button.primary{background:#1261a6;border-color:#1c7ed6;color:#fff;font-weight:600}",
    ".banner{position:fixed;pointer-events:auto;right:16px;bottom:16px;width:336px;background:#16212d;color:#e8eef5;",
    "  border:1px solid #2a3b4d;border-radius:12px;box-shadow:0 14px 36px rgba(0,0,0,.55);padding:13px 14px;",
    "  font:13px/1.5 system-ui,-apple-system,'Segoe UI','Microsoft YaHei',sans-serif}",
    ".banner h4{margin:0 0 8px;font-size:13px;color:#f2f7fc;display:flex;align-items:center;justify-content:space-between}",
    ".banner .f{display:flex;flex-direction:column;gap:3px;margin-bottom:8px}",
    ".banner .f span{font-size:11px;color:#8aa2b8}",
    ".banner .pwd-wrap{display:flex;gap:6px}",
    ".banner input{width:100%;box-sizing:border-box;padding:6px 8px;border-radius:7px;border:1px solid #2a3b4d;background:#0f1720;color:#e8eef5;font:12px/1.4 inherit;outline:none}",
    ".banner input:focus{border-color:#2b84d2}",
    ".banner .actions{display:flex;align-items:center;gap:6px;margin-top:10px}",
    ".banner .actions .spacer{flex:1}",
    ".banner button{pointer-events:auto;border-radius:8px;padding:6px 11px;font:12px/1.3 inherit;cursor:pointer;",
    "  border:1px solid #2a3b4d;background:#1f2e3d;color:#e8eef5}",
    ".banner button.muted-link{border:0;background:transparent;color:#8aa2b8;padding:4px 6px}",
    ".banner button.muted-link:hover{color:#e8eef5}",
    ".banner button.primary{background:#0b4f8a;border-color:#14639f;color:#fff;font-weight:600}",
  ].join("");

  function positionNearInput(el, targetEl) {
    if (!el || !targetEl || !visible(targetEl)) return false;
    const rect = targetEl.getBoundingClientRect();
    const top = Math.min(window.innerHeight - 180, Math.max(8, rect.bottom + 6));
    const left = Math.max(8, Math.min(rect.left, window.innerWidth - 356));
    el.style.left = left + "px";
    el.style.top = top + "px";
    return true;
  }

  function updateBadgePosition() {
    if (!badgeBtn || !badgeTarget || badgeBtn.style.display === "none") return;
    if (!visible(badgeTarget)) {
      badgeBtn.style.display = "none";
      return;
    }
    const r = badgeTarget.getBoundingClientRect();
    const top = r.top + Math.max(2, (r.height - 22) / 2);
    const left = Math.max(r.left + 4, r.right - 52);
    badgeBtn.style.top = top + "px";
    badgeBtn.style.left = left + "px";
  }

  function showInlineBadge(targetInput, count) {
    if (!targetInput || !count) {
      if (badgeBtn) badgeBtn.style.display = "none";
      return;
    }
    ensureShadow();
    badgeTarget = targetInput;
    badgeBtn.textContent = "🔑 " + count;
    badgeBtn.style.display = "inline-flex";
    updateBadgePosition();
  }

  function showLoginToast(items) {
    if (!isTopFrame || toastShownThisPage || !items?.length) return;
    toastShownThisPage = true;
    ensureShadow();
    toast.textContent = "";

    const first = items[0];
    const txt = document.createElement("span");
    txt.className = "txt";
    const label = first.username || first.name || "已存账号";
    txt.innerHTML = items.length > 1
      ? "KeyNexus 发现 <b>" + items.length + "</b> 个可用账号"
      : "使用 <b></b> 登录？";
    if (items.length === 1) txt.querySelector("b").textContent = label;

    const fillBtn = document.createElement("button");
    fillBtn.className = "primary";
    fillBtn.type = "button";
    fillBtn.textContent = "一键填充";
    fillBtn.addEventListener("click", () => {
      fill(first.id);
      toast.style.display = "none";
    });

    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.textContent = "×";
    closeBtn.addEventListener("click", () => {
      toast.style.display = "none";
    });

    toast.append(txt, fillBtn, closeBtn);
    toast.style.display = "flex";
    setTimeout(() => {
      if (toast) toast.style.display = "none";
    }, 7000);
  }

  function showPanel(input, items) {
    ensureShadow();
    panel.textContent = "";

    const header = document.createElement("header");
    const brand = document.createElement("span");
    brand.innerHTML = "<b>KeyNexus</b> 密码提示";
    const manualBtn = document.createElement("button");
    manualBtn.type = "button";
    manualBtn.className = "link-btn";
    manualBtn.textContent = "＋ 手动记密码";
    manualBtn.addEventListener("mousedown", (e) => {
      e.preventDefault();
      e.stopPropagation();
      hidePanel();
      openManualSaveBanner();
    });
    header.append(brand, manualBtn);
    panel.appendChild(header);

    if (!items.length) {
      const empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "当前网站暂无匹配账号，可点右上角手动录入";
      panel.appendChild(empty);
    }

    for (const item of items) {
      const row = document.createElement("button");
      row.className = "row";
      row.type = "button";

      const box = document.createElement("div");
      box.style.cssText = "min-width:0;display:flex;flex-direction:column";
      const name = document.createElement("div");
      name.className = "name";
      name.textContent = item.name || "(未命名)";
      const user = document.createElement("div");
      user.className = "user";
      user.textContent = item.username || "无用户名";
      box.append(name, user);
      row.appendChild(box);

      if (item.hasTotp) {
        const badge = document.createElement("span");
        badge.className = "badge";
        badge.textContent = "TOTP";
        row.appendChild(badge);
      }

      row.addEventListener("mousedown", (e) => {
        e.preventDefault();
        e.stopPropagation();
        fill(item.id);
        hidePanel();
      });
      panel.appendChild(row);
    }

    panel.style.display = "block";
    positionNearInput(panel, input);
  }

  function hidePanel() {
    if (panel) panel.style.display = "none";
  }

  async function fill(itemId) {
    const res = await send({ type: "fillData", id: itemId, url: location.href });
    if (!res || res.error || (!res.username && !res.password)) return;
    fillCredentials(res);
    if (toast) toast.style.display = "none";
  }

  /**
   * 展示保存 / 更新 / 手动提交密码卡片（支持直接改标题、账号、密码和「此站不再提示」）
   */
  function showSaveBanner({ action = "create", existingId = null, name = "", username = "", password = "", url = location.href, manual = false }) {
    if (!isTopFrame) return;
    ensureShadow();
    banner.textContent = "";

    const isUpdate = action === "update" && Boolean(existingId);
    const title = document.createElement("h4");
    title.textContent = manual
      ? "手动提交密码到 KeyNexus"
      : isUpdate
        ? "检测到密码变更，更新到 KeyNexus？"
        : "保存这个账号密码到 KeyNexus？";

    const nameWrap = document.createElement("label");
    nameWrap.className = "f";
    const nameLab = document.createElement("span");
    nameLab.textContent = "名称";
    const nameIn = document.createElement("input");
    nameIn.type = "text";
    nameIn.value = name || location.hostname;
    nameWrap.append(nameLab, nameIn);

    const userWrap = document.createElement("label");
    userWrap.className = "f";
    const userLab = document.createElement("span");
    userLab.textContent = "账号 / 用户名";
    const userIn = document.createElement("input");
    userIn.type = "text";
    userIn.value = username || "";
    userIn.placeholder = "邮箱 / 手机号 / 用户名";
    userWrap.append(userLab, userIn);

    const pwdWrap = document.createElement("div");
    pwdWrap.className = "f";
    const pwdLab = document.createElement("span");
    pwdLab.textContent = "密码";
    const pwdRow = document.createElement("div");
    pwdRow.className = "pwd-wrap";
    const pwdIn = document.createElement("input");
    pwdIn.type = "password";
    pwdIn.value = password || "";
    pwdIn.placeholder = "输入要保存的密码";
    const eyeBtn = document.createElement("button");
    eyeBtn.type = "button";
    eyeBtn.textContent = "显示";
    eyeBtn.addEventListener("click", () => {
      const hidden = pwdIn.type === "password";
      pwdIn.type = hidden ? "text" : "password";
      eyeBtn.textContent = hidden ? "隐藏" : "显示";
    });
    pwdRow.append(pwdIn, eyeBtn);
    pwdWrap.append(pwdLab, pwdRow);

    const actions = document.createElement("div");
    actions.className = "actions";

    if (!manual) {
      const neverBtn = document.createElement("button");
      neverBtn.type = "button";
      neverBtn.className = "muted-link";
      neverBtn.textContent = "此站不再提示";
      neverBtn.addEventListener("click", async () => {
        banner.style.display = "none";
        await send({ type: "neverSaveDomain", url });
      });
      actions.appendChild(neverBtn);
    }

    const spacer = document.createElement("span");
    spacer.className = "spacer";

    const cancelBtn = document.createElement("button");
    cancelBtn.type = "button";
    cancelBtn.textContent = "取消";
    cancelBtn.addEventListener("click", async () => {
      banner.style.display = "none";
      await send({ type: "dismissPendingCapture", url });
    });

    const saveBtn = document.createElement("button");
    saveBtn.type = "button";
    saveBtn.className = "primary";
    saveBtn.textContent = isUpdate ? "更新密码" : "保存";
    saveBtn.addEventListener("click", async () => {
      if (!pwdIn.value) {
        pwdIn.focus();
        return;
      }
      saveBtn.disabled = true;
      saveBtn.textContent = "加密保存中…";
      const res = await send({
        type: "save",
        existingId: isUpdate ? existingId : null,
        url,
        name: nameIn.value.trim() || location.hostname,
        username: userIn.value.trim(),
        password: pwdIn.value,
      });
      if (res?.error) {
        saveBtn.disabled = false;
        saveBtn.textContent = res.error === "locked" ? "请先点插件图标解锁" : "重试保存";
        return;
      }
      banner.style.display = "none";
      refreshPageCandidates(false);
    });

    actions.append(spacer, cancelBtn, saveBtn);
    banner.append(title, nameWrap, userWrap, pwdWrap, actions);
    banner.style.display = "block";
  }

  function openManualSaveBanner() {
    const pwds = passwordFields();
    const targetPwd = pickTargetPasswordForSave(pwds) || pwds[0] || null;
    const userEl = targetPwd ? guessUsernameField(targetPwd) : null;
    showSaveBanner({
      action: "create",
      name: document.title || location.hostname,
      username: userEl?.value || "",
      password: targetPwd?.value || "",
      url: location.href,
      manual: true,
    });
  }

  /* ------------------------------------------------ 登录框扫描与跨页面抓密 */

  async function refreshPageCandidates(allowToast = true) {
    const pwds = passwordFields();
    const otpInputs = Array.from(document.querySelectorAll("input")).filter((el) => visible(el) && isOtpInput(el));

    // 若出现了验证码框且开启了自动填 TOTP，自动补填（适配登录后第二步弹出 MFA 框的场景）
    if (otpInputs.length && settings.otpAutofill) {
      const targetOtp = otpInputs.find((el) => !otpFilledFor.has(el) && !el.value);
      if (targetOtp) {
        otpFilledFor.add(targetOtp);
        send({ type: "totpForUrl", url: location.href }).then((r) => {
          if (r?.code && !targetOtp.value) setValue(targetOtp, r.code);
        });
      }
    }

    if (!pwds.length) {
      if (badgeBtn) badgeBtn.style.display = "none";
      return;
    }

    const res = await send({ type: "candidates", url: location.href });
    if (!res || res.locked || !res.items?.length) {
      candidates = [];
      if (badgeBtn) badgeBtn.style.display = "none";
      return;
    }

    candidates = res.items;
    const primaryField = guessUsernameField(pwds[0]) || pwds[0];
    showInlineBadge(primaryField, candidates.length);

    if (allowToast && res.loginToast !== false && settings.loginToast !== false) {
      showLoginToast(candidates);
    }

    if (settings.autofillOnLoad && !pwds[0].value) {
      fill(candidates[0].id);
    }
  }

  /** 提交前同步抽取页面上的账号或密码，立即送进后台会话池 */
  function captureBeforeSubmit() {
    if (!settings.savePrompt) return;
    const pwds = passwordFields();
    const targetPwd = pickTargetPasswordForSave(pwds);

    if (!targetPwd) {
      // 没有密码框时，可能是分步登录第 1 步（只输账号点「下一步」）
      const userField = Array.from(document.querySelectorAll("input")).find(
        (el) => visible(el) && looksLikeUsernameField(el) && el.value.trim(),
      );
      if (userField) {
        send({ type: "stageUsername", url: location.href, username: userField.value.trim() });
      }
      return;
    }

    const userEl = guessUsernameField(targetPwd);
    const username = userEl?.value?.trim() || "";
    const password = targetPwd.value;
    if (!password) return;

    send({
      type: "stageCapture",
      url: location.href,
      title: document.title || location.hostname,
      username,
      password,
    }).then((res) => {
      // 如果 700ms 后页面没有跳转（SPA 登录或原地提交）且密码框已消失/隐藏，立即在当前页弹出保存卡片
      if (!res?.prompt || !res.capture) return;
      setTimeout(() => {
        const stillShowingSamePwd = passwordFields().some((p) => p.value === password);
        if (!stillShowingSamePwd || location.href !== lastKnownUrl) {
          showSaveBanner(res.capture);
        }
      }, 700);
    });
  }

  /** 页面加载完成或 SPA 路由变化后，检查上一页是否留下了待保存的密码 */
  async function checkPendingOnLand() {
    if (!isTopFrame) return;
    const res = await send({ type: "checkPendingCapture", url: location.href });
    if (!res?.capture) return;
    // 如果当前页面依然是同一个登录失败表单（密码框还在且报错），暂不乱弹；若已进入后台主页则立即提示保存
    const hasEmptyOrActiveLogin = passwordFields().length > 0 && location.href === res.capture.url;
    if (!hasEmptyOrActiveLogin) {
      showSaveBanner(res.capture);
    }
  }

  /* ----------------------------------------------------------------- 事件绑定 */

  function onFocusIn(e) {
    const el = e.target;
    if (!(el instanceof HTMLInputElement)) return;

    if (isOtpInput(el)) {
      if (otpFilledFor.has(el) || el.value) return;
      otpFilledFor.add(el);
      send({ type: "totpForUrl", url: location.href }).then((res) => {
        if (res?.code) setValue(el, res.code);
      });
      return;
    }

    if (!looksLikeLoginField(el)) return;
    activeInput = el;

    send({ type: "candidates", url: location.href }).then((res) => {
      if (!res || res.locked || !res.items?.length) {
        hidePanel();
        return;
      }
      candidates = res.items;
      showInlineBadge(el, res.items.length);
      showPanel(el, res.items);
    });
  }

  document.addEventListener("focusin", onFocusIn, true);

  // 分步登录：用户名输入框失焦时也暂存一份，防止网页是用 div 按钮切换下一步
  document.addEventListener(
    "change",
    (e) => {
      const el = e.target;
      if (el instanceof HTMLInputElement && looksLikeUsernameField(el) && el.value.trim()) {
        send({ type: "stageUsername", url: location.href, username: el.value.trim() });
      }
    },
    true,
  );

  // 滚动和窗口变化时跟随定位，而不是生硬关掉
  const onViewportMove = () => {
    requestAnimationFrame(() => {
      updateBadgePosition();
      if (panel && panel.style.display === "block" && activeInput) {
        if (!positionNearInput(panel, activeInput)) hidePanel();
      }
    });
  };
  window.addEventListener("scroll", onViewportMove, { passive: true, capture: true });
  window.addEventListener("resize", onViewportMove, { passive: true });

  document.addEventListener(
    "mousedown",
    (e) => {
      if (!shadow) return;
      const path = e.composedPath ? e.composedPath() : [];
      if (!path.includes(shadow.host) && e.target !== activeInput) hidePanel();
    },
    true,
  );

  // 在跳转发生前同步捕获表单账号密码（覆盖原生 submit、按 Enter、点击登录按钮三种方式）
  document.addEventListener("submit", captureBeforeSubmit, true);
  document.addEventListener(
    "keydown",
    (e) => {
      if (e.key === "Enter" && e.target instanceof HTMLInputElement) {
        captureBeforeSubmit();
      }
    },
    true,
  );
  document.addEventListener(
    "pointerdown",
    (e) => {
      const el = e.target;
      const btn =
        el instanceof Element
          ? el.closest('button, input[type="submit"], [role="button"], a[class*="btn" i], div[class*="btn" i]')
          : null;
      if (btn) captureBeforeSubmit();
    },
    true,
  );

  // 监听动态挂载的弹窗登录框 & SPA 路由切换
  let scanTimer = null;
  const observer = new MutationObserver(() => {
    if (location.href !== lastKnownUrl) {
      lastKnownUrl = location.href;
      toastShownThisPage = false;
      setTimeout(checkPendingOnLand, 300);
    }
    if (scanTimer) return;
    scanTimer = setTimeout(() => {
      scanTimer = null;
      refreshPageCandidates(true);
    }, 450);
  });
  if (document.documentElement) {
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }
  window.addEventListener("popstate", () => setTimeout(checkPendingOnLand, 250));
  window.addEventListener("hashchange", () => setTimeout(checkPendingOnLand, 250));

  // 后台 / 快捷键 / 右键菜单发来的指令
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.type === "cmd:fill-direct") {
      const done = fillCredentials({
        username: msg.username || "",
        password: msg.password || "",
        totp: msg.totp || "",
      });
      sendResponse({ ok: done });
      return true;
    }
    if (msg?.type === "cmd:fill-generated") {
      const target =
        (document.activeElement instanceof HTMLInputElement && !document.activeElement.readOnly
          ? document.activeElement
          : null) || passwordFields()[0];
      if (target && msg.password) {
        setValue(target, msg.password);
        navigator.clipboard?.writeText?.(msg.password).catch(() => {});
        sendResponse({ ok: true });
      } else {
        sendResponse({ ok: false });
      }
      return true;
    }
    if (msg?.type === "cmd:open-save-modal") {
      openManualSaveBanner();
      sendResponse({ ok: true });
      return true;
    }
    if (msg?.type !== "cmd:fill") return false;
    send({ type: "candidates", url: location.href }).then((res) => {
      if (res?.items?.length) {
        fill(res.items[0].id).then(() => sendResponse({ ok: true }));
      } else {
        if (isTopFrame) showPanel(passwordFields()[0] || document.body, []);
        sendResponse({ ok: false, reason: "no-match" });
      }
    });
    return true;
  });

  // 初始化：读取设置 -> 检查跨页待保存密码 -> 扫描当前页登录框
  send({ type: "settings" }).then((res) => {
    if (res && !res.error) settings = { ...settings, ...res };
    checkPendingOnLand();
    refreshPageCandidates(true);
  });
})();
