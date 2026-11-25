/**
 * TOTP / 域名匹配 / 桌面应用规则 / 生成器的单元测试。
 * 跑法：node test/util.test.mjs
 */
import { generateTotp, parseTotp, base32Encode, base32Decode } from "../src/lib/totp.js";
import {
  baseDomain, hostOf, matchesUrl, filterForUrl, buildDomainGroups,
  parseAppUri, matchesApp, hasAppUri, parseMobileUri, matchesMobileApp, resolveItemScope, isScopeApplicable,
} from "../src/lib/matcher.js";
import { generatePassword, generatePin, estimateStrength } from "../src/lib/generator.js";
import { compareSemver, parseGitHubRepo, resolveManifestUrl, resolveDownloadUrl, extractGitHubReleaseManifest, checkClientUpdate } from "../src/lib/updater.js";
import { deriveMasterKey, makeRegisterPayload, decryptPrivateKey } from "../src/lib/crypto.js";
import { unlockUserKey } from "../src/lib/vault.js";
import { PwdsvApi } from "../src/lib/api.js";

let pass = 0;
let fail = 0;
function eq(name, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (ok) {
    pass++;
    console.log("  ok   " + name);
  } else {
    fail++;
    console.error("  FAIL " + name + "\n       期望 " + JSON.stringify(expected) + "\n       实际 " + JSON.stringify(actual));
  }
}

console.log("[1] base32 往返");
{
  const raw = new Uint8Array([1, 2, 3, 4, 5, 250, 251, 252]);
  eq("encode->decode", Array.from(base32Decode(base32Encode(raw))), Array.from(raw));
  eq("RFC 4648 的 foo", base32Encode(new TextEncoder().encode("foo")), "MZXW6");
}

console.log("[2] TOTP（RFC 6238 附录 B，密钥 12345678901234567890）");
{
  const key = base32Encode(new TextEncoder().encode("12345678901234567890"));
  const cases = [
    [59, "94287082"],
    [1111111109, "07081804"],
    [1234567890, "89005924"],
    [2000000000, "69279037"],
  ];
  for (const [sec, expect8] of cases) {
    const totp = await generateTotp(key, sec * 1000);
    eq("t=" + sec, totp.code, String(expect8).slice(-6));
  }
}

console.log("[3] otpauth 解析");
{
  const cfg = parseTotp("otpauth://totp/GitHub:me%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30");
  eq("issuer", cfg.issuer, "GitHub");
  eq("account", cfg.account, "me@example.com");
  eq("secret", cfg.secret, "JBSWY3DPEHPK3PXP");
}

console.log("[4] 域名归一与同站点");
{
  eq("hostOf 去 www", hostOf("https://www.example.com/a/b?x=1"), "example.com");
  eq("非 http 不匹配", hostOf("ftp://example.com"), "");
  eq("baseDomain 常见后缀", baseDomain("a.b.example.co.uk"), "example.co.uk");
  eq("baseDomain 二级", baseDomain("login.example.com"), "example.com");
  eq("baseDomain 本地", baseDomain("localhost"), "localhost");
}

console.log("[5] 网站条目匹配");
{
  const item = { uris: [{ uri: "https://example.com/login", match: null }] };
  eq("同站点子域", matchesUrl(item, "https://accounts.example.com/signin"), true);
  eq("完全不相关", matchesUrl(item, "https://evil.com/"), false);
  eq("严格主机模式不跨子域", matchesUrl(item, "https://accounts.example.com/", { defaultPolicy: "host" }), false);

  const exact = { uris: [{ uri: "https://example.com/login", match: 3 }] };
  eq("精确匹配", matchesUrl(exact, "https://example.com/login"), true);
  eq("精确匹配不认多余路径", matchesUrl(exact, "https://example.com/login/x"), false);

  const never = { uris: [{ uri: "https://example.com", match: 5 }] };
  eq("永不匹配", matchesUrl(never, "https://example.com/"), false);

  const groups = buildDomainGroups({ globalEquivalentDomains: [{ type: 1, domains: ["youtube.com", "google.com"], excluded: false }] });
  const goog = { uris: [{ uri: "https://google.com", match: 0 }] };
  eq("等价域名组", matchesUrl(goog, "https://youtube.com/", { domainGroups: groups }), true);

  eq("一批里筛出对的", filterForUrl([{ uris: [{ uri: "https://a.com", match: null }] }, item], "https://example.com/x").length, 1);
}

console.log("[6] 桌面应用 app:// 规则解析与匹配");
{
  const parsed = parseAppUri("app://mstsc.exe?title=*远程桌面*");
  eq("parseAppUri exe", parsed?.exe, "mstsc.exe");
  eq("parseAppUri title", parsed?.title, "*远程桌面*");

  const appItem = { uris: [{ uri: "app://Navicat.exe", match: null }] };
  eq("hasAppUri 识别", hasAppUri(appItem), true);
  eq("网页匹配自动忽略 app://", matchesUrl(appItem, "https://navicat.exe/"), false);
  eq("应用大小写及路径归一匹配", matchesApp(appItem, { exe: "C:\\Program Files\\Navicat\\navicat.exe" }), true);
  eq("不匹配其他应用", matchesApp(appItem, { exe: "steam.exe" }), false);

  const dialogItem = { uris: [{ uri: "app://mstsc.exe?title=*登录*", match: null }] };
  eq("带窗口标题通配命中", matchesApp(dialogItem, { exe: "mstsc.exe", title: "Windows 安全 - 登录验证" }), true);
  eq("窗口标题不符不误触", matchesApp(dialogItem, { exe: "mstsc.exe", title: "远程桌面连接主界面" }), false);

  const mobItem = { pwdsvScope: "mobile", uris: [{ uri: "androidapp://com.cmbchina.ccd", match: null }] };
  eq("androidapp:// 包名解析", parseMobileUri("androidapp://com.cmbchina.ccd")?.packageName, "com.cmbchina.ccd");
  eq("手机专属条目匹配对应包名", matchesMobileApp(mobItem, { packageName: "com.cmbchina.ccd" }), true);
  eq("手机专属条目在电脑端不默认启用", isScopeApplicable(resolveItemScope(mobItem), "desktop"), false);

  const uniItem = { pwdsvScope: "universal", uris: [{ uri: "https://wx.qq.com" }, { uri: "app://WeChat.exe" }, { uri: "androidapp://com.tencent.mm" }] };
  eq("三端通用条目在网页/电脑/手机全端启用", ["web", "desktop", "mobile"].every((p) => isScopeApplicable(resolveItemScope(uniItem), p)), true);
  eq("三端通用条目匹配手机微信包名", matchesMobileApp(uniItem, { packageName: "com.tencent.mm" }), true);
}

console.log("[7] 生成器");
{
  const pwd = generatePassword({ length: 24, symbols: true });
  eq("长度", pwd.length, 24);
  eq("含四类字符", [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].every((r) => r.test(pwd)), true);
  eq("两次不撞", generatePassword({ length: 24 }) === generatePassword({ length: 24 }), false);
  eq("PIN 长度", generatePin(6).length, 6);
  eq("强度标签", estimateStrength("aB3!xY7@qW9#zR2$").label.length > 0, true);
}

console.log("[8] 四端版本更新与 GitHub Releases 检查器");
{
  eq("semver 升序", compareSemver("2.1.0", "2.0.0"), 1);
  eq("semver 相等忽略 v", compareSemver("v2.0.0", "2.0.0"), 0);
  eq("semver 降序", compareSemver("2.0.0-beta", "2.0.0"), -1);
  eq("解析 GitHub 简写仓库", parseGitHubRepo("orandoli/keynexus")?.apiUrl, "https://api.github.com/repos/orandoli/keynexus/releases/latest");
  eq("解析 GitHub 网页链接", parseGitHubRepo("https://github.com/orandoli/keynexus/releases")?.apiUrl, "https://api.github.com/repos/orandoli/keynexus/releases/latest");
  eq("默认清单地址", resolveManifestUrl("https://vault.example.com/", ""), "https://vault.example.com/client-releases/latest.json");
  eq("GitHub 仓库转 API 地址", resolveManifestUrl("https://vault.example.com", "orandoli/keynexus"), "https://api.github.com/repos/orandoli/keynexus/releases/latest");
  eq("相对下载地址拼接", resolveDownloadUrl("/client-releases/app.apk", "https://vault.example.com/client-releases/latest.json"), "https://vault.example.com/client-releases/app.apk");
  eq("绝对下载地址保持原样", resolveDownloadUrl("https://dl.example.com/app.apk", "https://vault.example.com/client-releases/latest.json"), "https://dl.example.com/app.apk");

  const ghCatalog = extractGitHubReleaseManifest({
    tag_name: "v2.2.0",
    body: "GitHub 发版测试",
    published_at: "2026-11-25T15:00:00Z",
    html_url: "https://github.com/orandoli/keynexus/releases/tag/v2.2.0",
    assets: [
      { name: "keynexus-android-2.2.0.apk", size: 3300000, digest: "sha256:" + "a".repeat(64), browser_download_url: "https://github.com/orandoli/keynexus/releases/download/v2.2.0/keynexus-android-2.2.0.apk" },
      { name: "keynexus-windows-2.2.0.exe", size: 18800000, digest: "sha256:" + "b".repeat(64), browser_download_url: "https://github.com/orandoli/keynexus/releases/download/v2.2.0/keynexus-windows-2.2.0.exe" },
      { name: "keynexus-extension-2.2.0.zip", size: 120000, browser_download_url: "https://github.com/orandoli/keynexus/releases/download/v2.2.0/keynexus-extension-2.2.0.zip" },
      { name: "keynexus-web-2.2.0.zip", size: 95000, browser_download_url: "https://github.com/orandoli/keynexus/releases/download/v2.2.0/keynexus-web-2.2.0.zip" },
    ],
  });
  eq("GitHub 解析版本号", ghCatalog.version, "2.2.0");
  eq("GitHub 提取桌面 exe", ghCatalog.desktop.downloadUrl.endsWith(".exe"), true);
  eq("GitHub 提取扩展 zip", ghCatalog.extension.downloadUrl.endsWith("extension-2.2.0.zip"), true);
  eq("GitHub 提取网页 zip", ghCatalog.web.downloadUrl.endsWith("web-2.2.0.zip"), true);
  eq("GitHub 提取 sha256 digest", ghCatalog.mobile.sha256, "a".repeat(64));

  const fakeFetch = async (url) => {
    if (url.includes("api.github.com")) {
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            tag_name: "v2.3.0",
            body: "GitHub Releases 新版上线",
            published_at: "2026-11-25T15:10:00Z",
            html_url: "https://github.com/orandoli/keynexus/releases/tag/v2.3.0",
            assets: [
              { name: "keynexus-windows-2.3.0.exe", size: 18800000, digest: "sha256:" + "c".repeat(64), browser_download_url: "https://github.com/orandoli/keynexus/releases/download/v2.3.0/keynexus-windows-2.3.0.exe" },
            ],
          });
        },
      };
    }
    return {
      ok: true,
      status: 200,
      async text() {
        return JSON.stringify({
          publishedAt: "2026-11-25T14:00:00Z",
          mobile: {
            version: "2.1.0",
            versionCode: 210,
            url: "/client-releases/keynexus-android-2.1.0.apk",
            sha256: "ABCD1234",
            notes: "支持前端一键更新",
          },
        });
      },
    };
  };
  const res = await checkClientUpdate({
    platform: "mobile",
    currentVersion: "2.0.0",
    currentVersionCode: 200,
    serverUrl: "https://127.0.0.1:18443",
    fetchImpl: fakeFetch,
  });
  eq("检测到新版更新", res.hasUpdate, true);
  eq("最新版本号", res.latestVersion, "2.1.0");
  eq("下载地址补全", res.downloadUrl, "https://127.0.0.1:18443/client-releases/keynexus-android-2.1.0.apk");
  eq("sha256 小写归一", res.sha256, "abcd1234");

  const ghRes = await checkClientUpdate({
    platform: "desktop",
    currentVersion: "2.0.0",
    customManifestUrl: "orandoli/keynexus",
    fetchImpl: fakeFetch,
  });
  eq("GitHub 源检测更新", ghRes.hasUpdate, true);
  eq("GitHub 源版本号", ghRes.latestVersion, "2.3.0");
  eq("GitHub 源 sha256", ghRes.sha256, "c".repeat(64));
}

console.log("[9] 零知识网页端注册载荷与密钥闭环");
{
  const payload = await makeRegisterPayload({
    email: "NewUser@Example.com",
    password: "Strong#Password2026",
    name: "测试用户",
    masterPasswordHint: "提示词",
    kdfIterations: 10000,
  });
  eq("邮箱小写化", payload.email, "newuser@example.com");
  eq("nickname 保留", payload.name, "测试用户");
  eq("masterPasswordHash 非空", Boolean(payload.masterPasswordHash && payload.masterPasswordHash.length > 20), true);
  eq("userKey 密文格式 2.", payload.key.startsWith("2."), true);
  eq("RSA publicKey 非空", Boolean(payload.keys?.publicKey && payload.keys.publicKey.length > 100), true);
  eq("RSA encryptedPrivateKey 格式 2.", payload.keys?.encryptedPrivateKey?.startsWith("2."), true);

  const mk = await deriveMasterKey("Strong#Password2026", payload.email, { kdf: payload.kdf, iterations: payload.kdfIterations });
  const { userKey } = await unlockUserKey({ key: payload.key }, mk);
  const pkcs8 = await decryptPrivateKey(userKey, payload.keys.encryptedPrivateKey);
  eq("RSA 私钥成功还原 PKCS8 字节", pkcs8 instanceof Uint8Array && pkcs8.length > 500, true);

  // 新版两步注册流程测试
  const calls2Step = [];
  const api2Step = new PwdsvApi("https://vault.example.com", {
    fetchImpl: async (url, init) => {
      calls2Step.push({ url, body: JSON.parse(init.body) });
      if (url.endsWith("/send-verification-email")) {
        return { ok: true, status: 200, async text() { return JSON.stringify("verify-jwt-token-123"); } };
      }
      return { ok: true, status: 200, async text() { return JSON.stringify({ object: "register" }); } };
    },
  });
  await api2Step.register(payload);
  eq("两步注册依次调用2次接口", calls2Step.length, 2);
  eq("两步注册携带 emailVerificationToken", calls2Step[1].body.emailVerificationToken, "verify-jwt-token-123");

  // 旧版 404 降级注册测试
  const callsLegacy = [];
  const apiLegacy = new PwdsvApi("https://vault.example.com", {
    fetchImpl: async (url, init) => {
      callsLegacy.push({ url, body: JSON.parse(init.body) });
      if (url.endsWith("/send-verification-email")) {
        return { ok: false, status: 404, async text() { return "<html>404</html>"; } };
      }
      return { ok: true, status: 200, async text() { return JSON.stringify({ object: "register" }); } };
    },
  });
  await apiLegacy.register(payload);
  eq("旧版404自动降级 /register", callsLegacy.map((c) => new URL(c.url).pathname), [
    "/identity/accounts/register/send-verification-email",
    "/identity/accounts/register",
  ]);
}

console.log("");
console.log(pass + " 通过, " + fail + " 失败");
process.exit(fail === 0 ? 0 : 1);
