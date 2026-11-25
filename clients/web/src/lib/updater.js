/**
 * 四端通用版本检测与自托管 / GitHub Releases 双源更新清单解析器：
 * - 支持直接填 GitHub 仓库（`user/repo` 或 `https://github.com/user/repo`），自动对接 GitHub Releases API 与 Release 附件
 * - 默认回退读取当前 PWDSV 服务器内置 `/client-releases/latest.json`
 * - 支持 Semantic Versioning 比对（忽略前导 v/V），Android 额外比对 versionCode
 */

import { normalizeServerUrl } from "./api.js";

/** 解析语义版本号为数字段 + 预发布标识 */
function parseSemver(raw) {
  const clean = String(raw || "")
    .trim()
    .replace(/^[vV]/, "");
  if (!clean) return { parts: [0, 0, 0], pre: "" };
  const [main, pre = ""] = clean.split("-", 2);
  const parts = main.split(".").map((n) => {
    const num = Number.parseInt(n, 10);
    return Number.isFinite(num) && num >= 0 ? num : 0;
  });
  while (parts.length < 3) parts.push(0);
  return { parts, pre };
}

/** 比较两个语义版本：a > b 返回 1，a < b 返回 -1，相等返回 0 */
export function compareSemver(a, b) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  const len = Math.max(pa.parts.length, pb.parts.length);
  for (let i = 0; i < len; i++) {
    const va = pa.parts[i] || 0;
    const vb = pb.parts[i] || 0;
    if (va > vb) return 1;
    if (va < vb) return -1;
  }
  if (!pa.pre && pb.pre) return 1;
  if (pa.pre && !pb.pre) return -1;
  if (pa.pre !== pb.pre) return pa.pre > pb.pre ? 1 : -1;
  return 0;
}

/** 识别 GitHub 仓库简写（owner/repo）、仓库 URL 或 Releases API URL */
export function parseGitHubRepo(input = "") {
  const raw = String(input || "").trim();
  if (!raw) return null;

  let owner = "";
  let repo = "";

  const shortMatch = raw.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?\/?$/);
  if (shortMatch) {
    [, owner, repo] = shortMatch;
  } else {
    const webMatch = raw.match(/^https?:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\.git)?(?:\/releases.*|\/)?$/i);
    const apiMatch = raw.match(/^https?:\/\/api\.github\.com\/repos\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+?)(?:\/releases.*|\/)?$/i);
    const m = webMatch || apiMatch;
    if (!m) return null;
    [, owner, repo] = m;
  }

  return {
    owner,
    repo,
    apiUrl: `https://api.github.com/repos/${owner}/${repo}/releases/latest`,
    releasesPageUrl: `https://github.com/${owner}/${repo}/releases/latest`,
  };
}

/** 计算更新源 URL（GitHub 仓库 -> GitHub Releases API；完整 URL -> 原样；留空 -> 服务器内置清单） */
export function resolveManifestUrl(serverUrl = "", customManifestUrl = "") {
  const custom = String(customManifestUrl || "").trim();
  if (custom) {
    const gh = parseGitHubRepo(custom);
    return gh ? gh.apiUrl : custom;
  }
  const base = normalizeServerUrl(serverUrl || "");
  if (!base) return "";
  return `${base}/client-releases/latest.json`;
}

/** 将清单里的相对或绝对下载地址解析为完整 URL */
export function resolveDownloadUrl(entryUrl, manifestUrl = "", serverUrl = "") {
  const raw = String(entryUrl || "").trim();
  if (!raw) return "";
  if (/^https?:\/\//i.test(raw)) return raw;
  const base = manifestUrl || (serverUrl ? `${normalizeServerUrl(serverUrl)}/` : "");
  if (!base) return raw;
  return new URL(raw, base).toString();
}

function normalizeAssetSha256(asset) {
  const direct = String(asset?.sha256 || "").trim().toLowerCase();
  if (direct) return direct;
  const digest = String(asset?.digest || "").trim();
  const m = digest.match(/^sha256:([a-f0-9]{64})$/i);
  return m ? m[1].toLowerCase() : "";
}

function pickBestAsset(assets, extRegex, preferredNameRegex) {
  const candidates = assets.filter((a) => extRegex.test(String(a?.name || "")));
  if (!candidates.length) return null;
  if (preferredNameRegex) {
    const hit = candidates.find((a) => preferredNameRegex.test(String(a?.name || "")));
    if (hit) return hit;
  }
  return candidates[0];
}

function toCatalogEntry(asset, version, notes) {
  if (!asset) return null;
  return {
    version,
    url: String(asset.browser_download_url || asset.url || ""),
    downloadUrl: String(asset.browser_download_url || asset.url || ""),
    sha256: normalizeAssetSha256(asset),
    size: Number(asset.size || 0),
    versionCode: Number(asset.versionCode || 0),
    notes,
  };
}

/** 从 GitHub Releases API 响应提取四端版本、附件下载地址与 SHA-256 */
export function extractGitHubReleaseManifest(releaseJson) {
  const version = String(releaseJson?.tag_name || releaseJson?.name || "")
    .trim()
    .replace(/^[vV]/, "");
  if (!version) {
    throw new Error("GitHub Release 缺少 tag_name 版本号");
  }
  const notes = String(releaseJson?.body || releaseJson?.name || "").trim();
  const publishedAt = String(releaseJson?.published_at || "");
  const releasePageUrl = String(releaseJson?.html_url || "");
  const assets = Array.isArray(releaseJson?.assets) ? releaseJson.assets : [];

  const mobileAsset = pickBestAsset(assets, /\.apk$/i, /android|mobile|keynexus|pwdsv/i);
  const desktopAsset = pickBestAsset(assets, /\.(exe|msi)$/i, /windows|desktop|keynexus|pwdsv/i);
  const extAsset = pickBestAsset(assets, /\.zip$/i, /ext|extension|chrome|edge/i);
  const webAsset = pickBestAsset(assets, /\.zip$/i, /web|vault/i);
  const jsonAsset = assets.find((a) => /^latest\.json$/i.test(String(a?.name || "")));

  return {
    sourceType: "github",
    version,
    publishedAt,
    notes,
    releasePageUrl,
    latestJsonUrl: String(jsonAsset?.browser_download_url || ""),
    mobile: toCatalogEntry(mobileAsset, version, notes),
    desktop: toCatalogEntry(desktopAsset, version, notes),
    extension: toCatalogEntry(extAsset, version, notes),
    web: toCatalogEntry(webAsset, version, notes) || {
      version,
      url: releasePageUrl,
      downloadUrl: releasePageUrl,
      sha256: "",
      size: 0,
      versionCode: 0,
      notes,
    },
  };
}

/** 拉取并归一化完整四端更新目录（支持自托管 latest.json 与 GitHub Releases） */
export async function fetchReleaseCatalog({
  serverUrl = "",
  customManifestUrl = "",
  fetchImpl = fetch,
}) {
  const manifestUrl = resolveManifestUrl(serverUrl, customManifestUrl);
  if (!manifestUrl) {
    throw new Error("请先设置服务器地址、GitHub 仓库（user/repo）或更新清单地址");
  }

  const res = await fetchImpl(manifestUrl, {
    method: "GET",
    cache: "no-store",
    headers: { Accept: "application/vnd.github+json, application/json" },
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`拉取更新信息失败 (HTTP ${res.status})`);
  }

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error("更新源返回的不是有效的 JSON 格式");
  }

  // 分支 A：GitHub Releases API 响应
  if (typeof data?.tag_name === "string" && Array.isArray(data?.assets)) {
    const parsed = extractGitHubReleaseManifest(data);
    // 若 Release 附件中同时上传了 latest.json，优先吸收其中的 sha256 与 versionCode
    if (parsed.latestJsonUrl) {
      try {
        const subRes = await fetchImpl(parsed.latestJsonUrl, {
          method: "GET",
          cache: "no-store",
          headers: { Accept: "application/json" },
        });
        if (subRes.ok) {
          const sub = JSON.parse(await subRes.text());
          for (const key of ["mobile", "desktop", "extension", "web"]) {
            if (!sub?.[key]) continue;
            const cur = parsed[key] || {};
            const subUrl = /^https?:\/\//i.test(String(sub[key].url || "")) ? sub[key].url : "";
            parsed[key] = {
              version: String(sub[key].version || cur.version || parsed.version),
              url: cur.downloadUrl || subUrl,
              downloadUrl: cur.downloadUrl || subUrl,
              sha256: String(sub[key].sha256 || cur.sha256 || "").trim().toLowerCase(),
              size: Number(cur.size || sub[key].size || 0),
              versionCode: Number(sub[key].versionCode || cur.versionCode || 0),
              notes: String(sub[key].notes || cur.notes || parsed.notes || ""),
            };
          }
        }
      } catch {
        /* 附件 latest.json 读取失败时继续使用 GitHub API 元数据 */
      }
    }
    return { ...parsed, manifestUrl };
  }

  // 分支 B：标准自托管 latest.json
  const out = {
    sourceType: "manifest",
    manifestUrl,
    publishedAt: String(data?.publishedAt || ""),
    notes: String(data?.notes || ""),
    releasePageUrl: "",
  };
  for (const key of ["mobile", "desktop", "extension", "web"]) {
    const e = data?.[key];
    if (!e || !e.version) {
      out[key] = null;
      continue;
    }
    const dl = resolveDownloadUrl(e.url || e.downloadUrl, manifestUrl, serverUrl);
    out[key] = {
      version: String(e.version).trim(),
      url: dl,
      downloadUrl: dl,
      sha256: String(e.sha256 || "").trim().toLowerCase(),
      size: Number(e.size || 0),
      versionCode: Number(e.versionCode || 0),
      notes: String(e.notes || data?.notes || ""),
    };
  }
  return out;
}

/**
 * 向更新源检查指定端是否有新版本。
 * @param {object} opts
 * @param {"mobile"|"desktop"|"extension"|"web"} opts.platform
 * @param {string} opts.currentVersion
 * @param {number} [opts.currentVersionCode]
 * @param {string} [opts.serverUrl]
 * @param {string} [opts.customManifestUrl]
 * @param {Function} [opts.fetchImpl]
 */
export async function checkClientUpdate({
  platform,
  currentVersion,
  currentVersionCode = 0,
  serverUrl = "",
  customManifestUrl = "",
  fetchImpl = fetch,
}) {
  const catalog = await fetchReleaseCatalog({ serverUrl, customManifestUrl, fetchImpl });
  const entry = catalog?.[platform];
  if (!entry || !entry.version) {
    throw new Error(`更新源中缺少 ${platform} 端版本或安装包附件`);
  }

  const latestVersion = String(entry.version).trim();
  const latestCode = Number(entry.versionCode || 0);
  const bySemver = compareSemver(latestVersion, currentVersion) > 0;
  const byAndroidCode =
    platform === "mobile" &&
    Number(currentVersionCode) > 0 &&
    latestCode > Number(currentVersionCode);

  return {
    hasUpdate: bySemver || byAndroidCode,
    sourceType: catalog.sourceType,
    platform,
    currentVersion: String(currentVersion || "0.0.0"),
    latestVersion,
    versionCode: latestCode,
    downloadUrl: entry.downloadUrl || "",
    sha256: entry.sha256 || "",
    size: Number(entry.size || 0),
    notes: String(entry.notes || catalog.notes || ""),
    publishedAt: String(catalog.publishedAt || ""),
    releasePageUrl: catalog.releasePageUrl || "",
    manifestUrl: catalog.manifestUrl,
  };
}
