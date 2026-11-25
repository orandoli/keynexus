// ==UserScript==
// @name         TOTP Auto-Paste | 验证码自动填入
// @namespace    https://github.com/heliannuuthus/blacksmith
// @version      1.1.0
// @description  Auto-paste TOTP verification code from clipboard when focusing on OTP input fields. Works with Bitwarden / Vaultwarden auto-copy.
// @description:zh-CN  聚焦验证码输入框时自动从剪贴板粘贴 TOTP，配合 Bitwarden / Vaultwarden 的自动复制功能使用
// @author       heliannuuthus
// @license      MIT
// @homepage     https://github.com/heliannuuthus/blacksmith/tree/main/scripts/totp-auto-paste
// @supportURL   https://github.com/heliannuuthus/blacksmith/issues
// @match        *://*/*
// @grant        none
// @run-at       document-idle
// @downloadURL https://update.greasyfork.org/scripts/569887/TOTP%20Auto-Paste%20%7C%20%E9%AA%8C%E8%AF%81%E7%A0%81%E8%87%AA%E5%8A%A8%E5%A1%AB%E5%85%A5.user.js
// @updateURL https://update.greasyfork.org/scripts/569887/TOTP%20Auto-Paste%20%7C%20%E9%AA%8C%E8%AF%81%E7%A0%81%E8%87%AA%E5%8A%A8%E5%A1%AB%E5%85%A5.meta.js
// ==/UserScript==

// ---------------------------------------------------------------------------
// 来源：GreasyFork #569887（https://greasyfork.org/zh-CN/scripts/569887）
//       作者 heliannuuthus，MIT 许可，上游仓库 github.com/heliannuuthus/blacksmith
// 抓取时间：2026-10-21。随本仓库分发，逻辑未改动，仅加这段说明。
//
// 为什么跟本项目配套：PWDSV 走的是 Bitwarden 那套客户端协议，客户端（桌面端/
// 浏览器插件）点「复制验证码」会把 TOTP 塞进系统剪贴板；这个脚本负责把剪贴板里
// 那 6 位数字直接填进当前页面的验证码输入框，省掉一次 Ctrl+V。
// 它靠 @match *://*/* 全站生效，不认域名、不认 DOM 品牌，所以项目改名成 PWDSV
// 之后照样能用，不需要改。
// ---------------------------------------------------------------------------

(function () {
  'use strict';

  const SELECTORS = [
    'input[autocomplete="one-time-code"]',
    'input[name*="totp" i]',
    'input[name*="otp" i]',
    'input[name*="mfa" i]',
    'input[name*="2fa" i]',
    'input[name*="verification" i]',
    'input[name*="verify" i]',
    'input[name*="passcode" i]',
    'input[name*="pin_code" i]',
    'input[name*="auth_code" i]',
    'input[name*="security_code" i]',
    'input[name*="two_factor" i]',
    'input[id*="otp" i]',
    'input[id*="totp" i]',
    'input[id*="2fa" i]',
    'input[id*="two-factor" i]',
    'input[id*="mfa" i]',
    'input[placeholder*="验证码"]',
    'input[placeholder*="安全码"]',
    'input[placeholder*="动态口令"]',
    'input[placeholder*="verification" i]',
    'input[placeholder*="one-time" i]',
    'input[placeholder*="6-digit" i]',
    'input[placeholder*="auth code" i]',
    'input[placeholder*="passcode" i]',
    'input[aria-label*="verification" i]',
    'input[aria-label*="code" i]',
    'input[aria-label*="one-time" i]',
    'input[aria-label*="two-factor" i]',
    'input[aria-label*="passcode" i]',
    'input[data-testid*="otp" i]',
    'input[data-testid*="totp" i]',
    'input[data-testid*="2fa" i]',
    'input[data-testid*="two-fa" i]',
    'input[data-testid*="mfa" i]',
    'input[inputmode="numeric"][maxlength="6"]',
  ];

  function findTotpInput() {
    for (const sel of SELECTORS) {
      const el = document.querySelector(sel);
      if (el && el.offsetParent !== null) return el;
    }
    return null;
  }

  async function tryPaste(input) {
    try {
      const text = await navigator.clipboard.readText();
      const code = text.replace(/[^0-9]/g, '').slice(0, 6);
      if (code.length === 6 && input.value !== code) {
        input.value = code;
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }
    } catch (_) {
      // clipboard permission denied — silent
    }
  }

  function watch(input) {
    if (input.dataset.totpWatched) return;
    input.dataset.totpWatched = 'true';
    input.addEventListener('focus', () => tryPaste(input));
    input.addEventListener('click', () => tryPaste(input));
    if (document.activeElement === input) tryPaste(input);
  }

  const observer = new MutationObserver(() => {
    const input = findTotpInput();
    if (input) watch(input);
  });

  observer.observe(document.body, { childList: true, subtree: true });

  const existing = findTotpInput();
  if (existing) watch(existing);
})();
