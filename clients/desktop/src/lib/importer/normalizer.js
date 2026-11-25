/**
 * 统一格式归一化、智能四态作用域推断（universal / web / desktop / mobile）与库内去重比对器。
 * 零外部路径耦合，可直接嵌入桌面端、手机端与 Node 测试环境。
 */

const VALID_SCOPES = new Set(["universal", "web", "desktop", "mobile"]);

function normalizeScopeLocal(raw) {
  const s = String(raw || "").trim().toLowerCase();
  return VALID_SCOPES.has(s) ? s : "";
}

function hostOfUrl(url) {
  try {
    const u = new URL(String(url));
    if (u.protocol !== "http:" && u.protocol !== "https:") return "";
    return u.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
}

const isAppRule = (u) => /^(?:app|winapp):\/\//i.test(String(u || "").trim());
const isMobRule = (u) => /^(?:androidapp|iosapp|mobileapp):\/\//i.test(String(u || "").trim());

// 常见多端统一账号平台词典：自动推荐为 universal，并在缺失 URI 时补齐常见域名/应用线索
const UNIVERSAL_PLATFORM_HINTS = [
  { re: /微信|wechat|weixin/i, web: "https://wx.qq.com", desktop: "app://WeChat.exe", mobile: "androidapp://com.tencent.mm" },
  { re: /\bqq\b|腾讯qq/i, web: "https://im.qq.com", desktop: "app://QQ.exe", mobile: "androidapp://com.tencent.mobileqq" },
  { re: /飞书|feishu|lark/i, web: "https://www.feishu.cn", desktop: "app://Feishu.exe", mobile: "androidapp://com.ss.android.lark" },
  { re: /钉钉|dingtalk/i, web: "https://www.dingtalk.com", desktop: "app://DingTalk.exe", mobile: "androidapp://com.alibaba.android.rimet" },
  { re: /github/i, web: "https://github.com/login", desktop: "", mobile: "androidapp://com.github.android" },
  { re: /google|gmail/i, web: "https://accounts.google.com", desktop: "", mobile: "androidapp://com.google.android.gm" },
  { re: /bilibili|b站|哔哩/i, web: "https://passport.bilibili.com", desktop: "", mobile: "androidapp://tv.danmaku.bili" },
  { re: /steam/i, web: "https://store.steampowered.com/login", desktop: "app://steam.exe", mobile: "androidapp://com.valvesoftware.android.steam.community" },
  { re: /telegram/i, web: "https://web.telegram.org", desktop: "app://Telegram.exe", mobile: "androidapp://org.telegram.messenger" },
  { re: /microsoft|outlook|onedrive/i, web: "https://login.microsoftonline.com", desktop: "", mobile: "" },
];

const DESKTOP_KEYWORDS = /navicat|xshell|mobaxterm|dbeaver|datagrip|mstsc|远程桌面|rdp|putty|winscp|todesk|sunlogin|向日葵|anydesk|\.exe\b|客户端专用|电脑端/i;
const MOBILE_KEYWORDS = /手机银行|掌上生活|云闪付|学习强国|app专用|手机端|手势密码|androidapp:/i;

const CN_SCOPE_ALIAS = {
  "通用": "universal",
  "三端通用": "universal",
  "全端": "universal",
  "多端": "universal",
  "网页": "web",
  "网页端": "web",
  "网站": "web",
  "电脑": "desktop",
  "电脑端": "desktop",
  "桌面": "desktop",
  "桌面端": "desktop",
  "pc": "desktop",
  "windows": "desktop",
  "手机": "mobile",
  "手机端": "mobile",
  "移动端": "mobile",
  "安卓": "mobile",
  "app": "mobile",
};

/** 从大模型可能带代码块或前后缀的文本中稳健提取 JSON 对象/数组 */
export function extractJsonFromModelOutput(rawText) {
  const s = String(rawText || "").trim();
  if (!s) throw new Error("模型返回为空");

  const fenced = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenced ? fenced[1].trim() : s;

  for (const text of [candidate, s]) {
    try {
      return JSON.parse(text);
    } catch {
      const firstBrace = text.indexOf("{");
      const lastBrace = text.lastIndexOf("}");
      if (firstBrace >= 0 && lastBrace > firstBrace) {
        try {
          return JSON.parse(text.slice(firstBrace, lastBrace + 1));
        } catch {
          /* 继续尝试数组 */
        }
      }
      const firstBracket = text.indexOf("[");
      const lastBracket = text.lastIndexOf("]");
      if (firstBracket >= 0 && lastBracket > firstBracket) {
        try {
          return JSON.parse(text.slice(firstBracket, lastBracket + 1));
        } catch {
          /* 抛出下方统一错误 */
        }
      }
    }
  }
  throw new Error("无法将模型输出解析为合法 JSON，请重试或更换指令遵循能力更强的模型");
}

function cleanUriEntry(raw) {
  const u = String(raw || "").trim();
  if (!u) return "";
  if (/^(?:https?|app|winapp|androidapp|iosapp|mobileapp):\/\//i.test(u)) return u;
  if (/\.exe$/i.test(u)) return "app://" + u.replace(/^.*[\\/]/, "");
  if (/^com\.[a-z0-9_]+(\.[a-z0-9_]+)+$/i.test(u)) return "androidapp://" + u.toLowerCase();
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+(?:[/:].*)?$/i.test(u)) return "https://" + u;
  return u;
}

/** 智能推断四态密码作用域 + 自动补全常见平台多端 URI */
export function normalizeSingleRecord(raw, sourceLabel = "") {
  const name = String(raw?.name || raw?.title || raw?.service || "").trim();
  const username = String(raw?.username || raw?.account || raw?.user || raw?.email || "").trim();
  const password = String(raw?.password || raw?.pass || raw?.secret || "").trim();
  const totp = String(raw?.totp || raw?.otp || "").trim();
  const folderName = String(raw?.folderName || raw?.folder || "").trim();
  const notes = String(raw?.notes || raw?.note || "").trim();

  let rawUris = [];
  if (Array.isArray(raw?.uris)) {
    rawUris = raw.uris.map((u) => (typeof u === "string" ? u : u?.uri || ""));
  } else if (raw?.uri || raw?.url) {
    rawUris = [String(raw.uri || raw.url)];
  }
  const uris = [...new Set(rawUris.map(cleanUriEntry).filter(Boolean))];

  const rawScopeStr = String(raw?.pwdsvScope || raw?.scope || "").trim().toLowerCase();
  let scope = normalizeScopeLocal(rawScopeStr) || CN_SCOPE_ALIAS[rawScopeStr] || "";

  const combinedText = `${name} ${notes} ${uris.join(" ")}`;
  const knownPlatform = UNIVERSAL_PLATFORM_HINTS.find((h) => h.re.test(name) || h.re.test(uris.join(" ")));

  if (knownPlatform) {
    if (!scope) scope = "universal";
    if (scope === "universal") {
      if (knownPlatform.web && !uris.some((u) => /^https?:/i.test(u))) uris.push(knownPlatform.web);
      if (knownPlatform.desktop && !uris.some((u) => isAppRule(u))) uris.push(knownPlatform.desktop);
      if (knownPlatform.mobile && !uris.some((u) => isMobRule(u))) uris.push(knownPlatform.mobile);
    }
  }

  if (!scope) {
    const hasWeb = uris.some((u) => /^https?:/i.test(u));
    const hasDesk = uris.some((u) => isAppRule(u));
    const hasMob = uris.some((u) => isMobRule(u));
    const platformCount = [hasWeb, hasDesk, hasMob].filter(Boolean).length;

    if (platformCount >= 2) scope = "universal";
    else if (hasDesk || DESKTOP_KEYWORDS.test(combinedText)) scope = "desktop";
    else if (hasMob || MOBILE_KEYWORDS.test(combinedText)) scope = "mobile";
    else if (hasWeb) scope = "web";
    else scope = "universal";
  }

  const finalName = name || hostOfUrl(uris[0] || "") || uris[0] || username || "未命名账号";

  return {
    name: finalName,
    username,
    password,
    totp,
    uris,
    pwdsvScope: scope,
    folderName,
    notes: notes || (sourceLabel ? `识别自：${sourceLabel}` : ""),
    confidence: Math.max(0, Math.min(1, Number(raw?.confidence ?? 0.9))),
  };
}

/**
 * 批量归一化并与当前密码库已有条目比对，标记「新建 create / 覆盖更新密码 update / 完全重复 skip」
 */
export function normalizeAndCompareRecords(rawItems, existingVaultItems = [], sourceLabel = "") {
  const arr = Array.isArray(rawItems)
    ? rawItems
    : Array.isArray(rawItems?.items)
      ? rawItems.items
      : Array.isArray(rawItems?.credentials)
        ? rawItems.credentials
        : [];

  const results = [];
  for (const r of arr) {
    const norm = normalizeSingleRecord(r, sourceLabel);
    if (!norm.password && !norm.username) continue;

    const normHost = hostOfUrl(norm.uris.find((u) => /^https?:/i.test(u)) || "");
    const matchExisting = (existingVaultItems || []).find((ex) => {
      const sameUser = (ex.username || "").toLowerCase() === norm.username.toLowerCase();
      if (!sameUser) return false;
      if (normHost) {
        const exHasHost = (ex.uris || []).some((u) => hostOfUrl(u.uri || "") === normHost);
        if (exHasHost) return true;
      }
      return (ex.name || "").trim().toLowerCase() === norm.name.trim().toLowerCase();
    });

    let duplicateAction = "create";
    let existingId = null;
    let selected = true;

    if (matchExisting) {
      existingId = matchExisting.id;
      if ((matchExisting.password || "") === norm.password) {
        duplicateAction = "skip";
        selected = false;
      } else {
        duplicateAction = "update";
      }
    }

    results.push({
      ...norm,
      duplicateAction,
      existingId,
      selected,
    });
  }
  return results;
}
