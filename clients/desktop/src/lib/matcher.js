/**
 * 跨端匹配与四态密码作用域（Scope）引擎：
 *
 * 1. 四态密码作用域（pwdsvScope）：
 *    - "universal"：三端通用统一账户（网页 + 电脑软件 + 手机 App 互通，同号同密）
 *    - "web"      ：网页端专属密码
 *    - "desktop"  ：电脑客户端专属密码
 *    - "mobile"   ：手机客户端专属密码
 *
 * 2. 多端 URI 协议：
 *    - 网站规则   ：https://example.com/login
 *    - 桌面端规则 ：app://WeChat.exe 或 app://mstsc.exe?title=*远程桌面*
 *    - 手机端规则 ：androidapp://com.tencent.mm 或 iosapp://com.tencent.xin
 */

export const PWDSV_SCOPES = Object.freeze(["universal", "web", "desktop", "mobile"]);

export const SCOPE_LABELS = Object.freeze({
  universal: "三端通用",
  web: "网页端",
  desktop: "电脑端",
  mobile: "手机端",
});

export function normalizeScope(raw) {
  const s = String(raw || "").trim().toLowerCase();
  return PWDSV_SCOPES.includes(s) ? s : "";
}

/**
 * 判断某作用域在目标端是否默认启用（本端专属 + 三端通用）
 * @param {string} scope "universal" | "web" | "desktop" | "mobile"
 * @param {"web"|"desktop"|"mobile"} platform
 */
export function isScopeApplicable(scope, platform) {
  const s = normalizeScope(scope) || "universal";
  if (s === "universal") return true;
  return s === platform;
}

// 常见的多段顶级后缀，用来算「同站点」。
const MULTI_SUFFIX = new Set([
  "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
  "co.kr", "or.kr", "ne.kr",
  "com.tw", "org.tw", "net.tw", "edu.tw", "gov.tw",
  "com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk",
  "com.sg", "org.sg", "net.sg", "edu.sg", "gov.sg",
  "com.br", "net.br", "org.br", "gov.br",
  "com.mx", "org.mx", "gob.mx",
  "co.nz", "org.nz", "net.nz",
  "co.za", "org.za", "net.za",
  "co.in", "net.in", "org.in", "gov.in",
  "com.tr", "com.ar", "com.co", "com.pe", "com.ve", "com.uy",
  "co.il", "co.th", "co.id", "com.my", "com.ph", "com.vn", "com.pk", "com.eg",
  "github.io", "gitlab.io", "herokuapp.com", "vercel.app", "netlify.app",
  "pages.dev", "workers.dev", "azurewebsites.net", "cloudfront.net",
  "s3.amazonaws.com", "appspot.com", "blogspot.com", "heroku.com",
  "edu.cn.com", "gouv.fr", "asso.fr", "co.fr",
]);

export function hostOf(url) {
  try {
    const u = new URL(String(url));
    if (u.protocol !== "http:" && u.protocol !== "https:") return "";
    return u.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
}

export function baseDomain(host) {
  const h = String(host || "").toLowerCase();
  if (!h) return "";
  const parts = h.split(".");
  if (parts.length <= 2) return h;
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_SUFFIX.has(lastTwo)) return parts.slice(-3).join(".");
  return lastTwo;
}

export function buildDomainGroups(domains) {
  const map = new Map();
  if (!domains) return map;
  let groupId = 0;

  const addGroup = (list) => {
    if (!Array.isArray(list) || list.length < 2) return;
    const id = groupId++;
    for (const d of list) {
      if (typeof d !== "string") continue;
      const key = d.toLowerCase().replace(/^www\./, "");
      if (!key || key.startsWith("globalequivalentdomains")) continue;
      if (!map.has(key)) map.set(key, id);
    }
  };

  for (const g of domains.globalEquivalentDomains || []) {
    if (g && !g.excluded && Array.isArray(g.domains)) addGroup(g.domains);
  }
  for (const g of domains.equivalentDomains || []) addGroup(g);
  return map;
}

/**
 * 解析桌面应用 URI（例如 app://navicat.exe 或 app://mstsc.exe?title=*远程*）
 */
export function parseAppUri(uri) {
  const raw = String(uri || "").trim();
  const m = raw.match(/^(?:app|winapp):\/\/([^/?#]+)(?:\?([^#]*))?/i);
  if (!m) return null;
  const exe = decodeURIComponent(m[1]).trim().toLowerCase();
  if (!exe) return null;
  let title = null;
  if (m[2]) {
    const params = new URLSearchParams(m[2]);
    const t = params.get("title");
    if (t && t.trim()) title = t.trim();
  }
  return { exe, title };
}

/**
 * 解析手机应用 URI（例如 androidapp://com.tencent.mm 或 mobileapp://com.github.android）
 */
export function parseMobileUri(uri) {
  const raw = String(uri || "").trim();
  const m = raw.match(/^(?:androidapp|iosapp|mobileapp):\/\/([^/?#]+)/i);
  if (!m) return null;
  const pkg = decodeURIComponent(m[1]).trim().toLowerCase();
  return pkg ? { packageName: pkg } : null;
}

export function hasAppUri(item) {
  return (item?.uris || []).some((u) => Boolean(parseAppUri(typeof u === "string" ? u : u?.uri)));
}

export function hasMobileUri(item) {
  return (item?.uris || []).some((u) => Boolean(parseMobileUri(typeof u === "string" ? u : u?.uri)));
}

export function hasWebUri(item) {
  return (item?.uris || []).some((u) => {
    const raw = String(typeof u === "string" ? u : u?.uri || "").trim();
    if (!raw || parseAppUri(raw) || parseMobileUri(raw)) return false;
    return !/^[a-z][a-z0-9+.-]*:/i.test(raw) || /^https?:/i.test(raw);
  });
}

/**
 * 综合服务端 pwdsvScope、加密字段 _pwdsv_scope 以及旧数据 URI 形态，解析条目的最终四态作用域
 */
export function resolveItemScope(item) {
  const fieldVal = (item?.fields || []).find((f) => f?.name === "_pwdsv_scope")?.value;
  // 若客户端加密字段明确标了，或服务端返回了非默认的显式值
  const explicitField = normalizeScope(fieldVal);
  if (explicitField) return explicitField;

  const explicitServer = normalizeScope(item?.pwdsvScope);
  if (explicitServer && explicitServer !== "universal") return explicitServer;

  // 对尚未手动标记的老数据做智能归类：纯 app:// 归 desktop，纯 androidapp:// 归 mobile，其余归 universal
  const web = hasWebUri(item);
  const desk = hasAppUri(item);
  const mob = hasMobileUri(item);
  if (desk && !web && !mob) return "desktop";
  if (mob && !web && !desk) return "mobile";
  return explicitServer || "universal";
}

export function wildcardMatch(pattern, text) {
  if (!pattern) return true;
  const escaped = String(pattern)
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp("^" + escaped + "$", "i").test(String(text || ""));
}

export function matchesApp(item, { exe, title = "" } = {}) {
  const rawExe = String(exe || "").trim().toLowerCase().replace(/^.*[\\/]/, "");
  if (!rawExe) return false;
  const normExe = rawExe.endsWith(".exe") ? rawExe : rawExe + ".exe";

  for (const entry of item?.uris || []) {
    if (entry?.match === 5) continue;
    const rule = parseAppUri(entry?.uri);
    if (!rule) continue;
    const targetExe = rule.exe.endsWith(".exe") ? rule.exe : rule.exe + ".exe";
    if (targetExe !== normExe) continue;
    if (rule.title && !wildcardMatch(rule.title, title)) continue;
    return true;
  }
  return false;
}

/**
 * 判断单条记录是否匹配手机端当前打开的 App 包名（或手机浏览器网页域名）
 */
export function matchesMobileApp(item, { packageName = "", webDomain = "" } = {}, opts = {}) {
  const scope = resolveItemScope(item);
  if (!isScopeApplicable(scope, "mobile")) return false;

  const pkg = String(packageName || "").trim().toLowerCase();
  if (pkg) {
    for (const entry of item?.uris || []) {
      if (entry?.match === 5) continue;
      const rule = parseMobileUri(entry?.uri);
      if (rule && rule.packageName === pkg) return true;
    }
  }

  if (webDomain) {
    const url = /^https?:/i.test(webDomain) ? webDomain : "https://" + webDomain;
    if (matchesUrl(item, url, opts)) return true;
  }
  return false;
}

function normalizeUri(uri) {
  let s = String(uri || "").trim();
  if (!s) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(s)) {
    if (!/^https?:/i.test(s)) return null;
    return s;
  }
  return "https://" + s;
}

export function matchesUrl(item, pageUrl, opts = {}) {
  const uris = item?.uris || [];
  if (!uris.length) return false;

  const page = normalizeUri(pageUrl);
  if (!page) return false;
  const pageHost = hostOf(page);
  if (!pageHost) return false;

  const policy = opts.defaultPolicy || "baseDomain";
  const groups = opts.domainGroups || new Map();
  const pageBase = baseDomain(pageHost);
  const pageGroup = groups.get(pageHost) ?? groups.get(pageBase);

  for (const entry of uris) {
    const target = normalizeUri(entry?.uri);
    if (!target) continue;
    const mode = entry?.match ?? null;

    if (mode === 5) continue;
    if (mode === 3) {
      if (target.toLowerCase() === page.toLowerCase()) return true;
      continue;
    }
    if (mode === 2) {
      if (page.toLowerCase().startsWith(target.toLowerCase())) return true;
      continue;
    }
    if (mode === 4) {
      try {
        if (new RegExp(target, "i").test(page)) return true;
      } catch {
        /* 忽略非法正则 */
      }
      continue;
    }

    const targetHost = hostOf(target);
    if (!targetHost) continue;

    if (mode === 1 || (mode === null && policy === "host")) {
      if (targetHost === pageHost) return true;
      continue;
    }

    if (targetHost === pageHost) return true;
    if (baseDomain(targetHost) === pageBase) return true;
    if (pageGroup !== undefined) {
      const targetGroup = groups.get(targetHost) ?? groups.get(baseDomain(targetHost));
      if (targetGroup !== undefined && targetGroup === pageGroup) return true;
    }
  }
  return false;
}

export function filterForUrl(items, pageUrl, opts = {}) {
  return (items || []).filter((it) => {
    if (opts.respectScope && !isScopeApplicable(resolveItemScope(it), "web")) return false;
    return matchesUrl(it, pageUrl, opts);
  });
}

export function rankCandidates(items, pageUrl) {
  const host = hostOf(pageUrl);
  return [...items].sort((a, b) => {
    const score = (it) => {
      let s = 0;
      if (host && (it.uris || []).some((u) => hostOf(normalizeUri(u?.uri) || "") === host)) s += 4;
      if (it.favorite) s += 2;
      if (it.username) s += 1;
      return s;
    };
    return score(b) - score(a);
  });
}
