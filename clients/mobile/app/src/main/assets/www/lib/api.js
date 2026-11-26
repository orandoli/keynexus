/**
 * PWDSV / Bitwarden 兼容 REST 客户端（支持浏览器插件、Windows 桌面端、Android 手机端共用）。
 *
 * 端点：
 *   POST   /identity/accounts/prelogin     拿 KDF 参数
 *   POST   /identity/connect/token         登录 / 刷新 / 2FA
 *   POST   /api/two-factor/send-email-login 触发邮件两步验证码
 *   GET    /api/sync                       拉全量（或按 ?scope= 筛选）数据
 *   GET    /api/pwdsv/scope-stats          获取服务端四态密码作用域与来源统计
 *   POST   /api/ciphers                    新建条目
 *   POST   /api/ciphers/import             批量加密导入条目与文件夹
 *   PUT    /api/ciphers/<id>               更新条目
 *   DELETE /api/ciphers/<id>               删除条目
 *   GET    /api/config                     探活
 */

export const CLIENT_NAME = "browser";
export const CLIENT_VERSION = "2026.2.0";
export const DEVICE_TYPE = 2; // 0=Android, 1=iOS, 2=Chrome Extension, 6=Windows Desktop

export class ApiError extends Error {
  constructor(message, status, payload) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

export function normalizeServerUrl(input) {
  let s = String(input || "").trim();
  if (!s) throw new ApiError("服务器地址是空的", 0);
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  return s.replace(/\/+$/, "");
}

export function buildWebSocketUrl(serverUrl, accessToken) {
  const base = normalizeServerUrl(serverUrl);
  const wsBase = base.replace(/^http:/i, "ws:").replace(/^https:/i, "wss:");
  return wsBase + "/notifications/hub?access_token=" + encodeURIComponent(accessToken);
}

export class PwdsvApi {
  /**
   * @param {string} baseUrl
   * @param {{
   *   deviceId?:string,
   *   deviceName?:string,
   *   deviceType?:number,
   *   clientName?:string,
   *   fetchImpl?:typeof fetch,
   * }} [opts]
   */
  constructor(baseUrl, opts = {}) {
    this.baseUrl = normalizeServerUrl(baseUrl);
    this.deviceId = opts.deviceId || "";
    this.deviceName = opts.deviceName || "PWDSV 客户端";
    this.deviceType = opts.deviceType ?? DEVICE_TYPE;
    this.clientName = opts.clientName || CLIENT_NAME;
    this.fetchImpl = opts.fetchImpl || ((...args) => fetch(...args));
  }

  headers(extra = {}) {
    const h = {
      Accept: "application/json",
      "Bitwarden-Client-Name": this.clientName,
      "Bitwarden-Client-Version": CLIENT_VERSION,
      "Device-Type": String(this.deviceType),
      ...extra,
    };
    if (this.deviceId) h["Device-Identifier"] = this.deviceId;
    return h;
  }

  async request(path, { method = "GET", body, token, form, headers = {} } = {}) {
    const url = this.baseUrl + path;
    const init = { method, headers: this.headers(headers) };

    if (token) init.headers.Authorization = "Bearer " + token;
    if (form) {
      init.headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8";
      init.body = new URLSearchParams(form).toString();
    } else if (body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }

    let res;
    try {
      res = await this.fetchImpl(url, init);
    } catch (e) {
      throw new ApiError("连不上服务器：" + (e?.message || e), 0);
    }

    const text = await res.text();
    let data = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = text;
      }
    }

    if (!res.ok) {
      const textErr = typeof data === "string" ? data.trim() : "";
      const isHtml = textErr.startsWith("<");
      const msg =
        (data && (data.error_description || data.message || data.error || data.errorModel?.message)) ||
        (!isHtml && textErr) ||
        "HTTP " + res.status;
      throw new ApiError(String(msg), res.status, data);
    }
    return data;
  }

  async prelogin(email) {
    const data = await this.request("/identity/accounts/prelogin", {
      method: "POST",
      body: { email: String(email || "").trim() },
    });
    return {
      kdf: Number(data?.kdf ?? 0),
      iterations: Number(data?.kdfIterations ?? data?.kdfSettings?.iterations ?? 600000),
      memory: Number(data?.kdfMemory ?? data?.kdfSettings?.memory ?? 64),
      parallelism: Number(data?.kdfParallelism ?? data?.kdfSettings?.parallelism ?? 4),
    };
  }

  async login({ email, masterPasswordHash, twoFactorToken, twoFactorProvider, remember = false }) {
    const form = {
      grant_type: "password",
      scope: "api offline_access",
      client_id: this.clientName,
      deviceType: String(this.deviceType),
      deviceIdentifier: this.deviceId,
      deviceName: this.deviceName,
      username: String(email || "").trim(),
      password: masterPasswordHash,
    };
    if (twoFactorToken) {
      form.twoFactorToken = twoFactorToken;
      form.twoFactorProvider = String(twoFactorProvider ?? 0);
      form.twoFactorRemember = remember ? "1" : "0";
    }

    const data = await this.request("/identity/connect/token", { method: "POST", form });
    return {
      accessToken: data?.access_token,
      refreshToken: data?.refresh_token,
      expiresIn: Number(data?.expires_in || 3600),
    };
  }

  async sendEmailLoginOtp({ email, masterPasswordHash }) {
    return this.request("/api/two-factor/send-email-login", {
      method: "POST",
      body: {
        email: String(email || "").trim(),
        masterPasswordHash,
        deviceIdentifier: this.deviceId,
      },
    });
  }

  async refresh(refreshToken) {
    const data = await this.request("/identity/connect/token", {
      method: "POST",
      form: {
        grant_type: "refresh_token",
        client_id: this.clientName,
        refresh_token: refreshToken,
      },
    });
    return {
      accessToken: data?.access_token,
      refreshToken: data?.refresh_token,
      expiresIn: Number(data?.expires_in || 3600),
    };
  }

  async sync(accessToken, { scope = "" } = {}) {
    const qs = scope ? "?scope=" + encodeURIComponent(scope) : "";
    return this.request("/api/sync" + qs, { token: accessToken });
  }

  async scopeStats(accessToken) {
    return this.request("/api/pwdsv/scope-stats", { token: accessToken });
  }

  async config() {
    return this.request("/api/config");
  }

  async register(payload) {
    let tokenRes;
    try {
      tokenRes = await this.request("/identity/accounts/register/send-verification-email", {
        method: "POST",
        body: {
          email: payload.email,
          name: payload.name || "",
        },
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        return this.request("/identity/accounts/register", {
          method: "POST",
          body: payload,
        });
      }
      throw err;
    }

    const emailVerificationToken = typeof tokenRes === "string" ? tokenRes.trim() : "";
    if (!emailVerificationToken) {
      throw new ApiError("服务端已开启邮箱验证，请前往邮箱点击验证链接完成注册", 202);
    }

    return this.request("/identity/accounts/register/finish", {
      method: "POST",
      body: {
        ...payload,
        emailVerificationToken,
      },
    });
  }

  async createCipher(accessToken, payload) {
    return this.request("/api/ciphers", { method: "POST", token: accessToken, body: payload });
  }

  async importCiphers(accessToken, { ciphers, folders = [], folderRelationships = [] }) {
    return this.request("/api/ciphers/import", {
      method: "POST",
      token: accessToken,
      body: { ciphers, folders, folderRelationships },
    });
  }

  async updateCipher(accessToken, id, payload) {
    return this.request("/api/ciphers/" + encodeURIComponent(id), {
      method: "PUT",
      token: accessToken,
      body: payload,
    });
  }

  async deleteCipher(accessToken, id) {
    await this.request("/api/ciphers/" + encodeURIComponent(id), { method: "DELETE", token: accessToken });
  }
}

export function parseTwoFactorProviders(err) {
  const payload = err?.payload;
  if (!payload || !Array.isArray(payload.TwoFactorProviders)) return [];
  const names = {
    0: "验证器 App (TOTP)",
    1: "邮箱验证码",
    2: "Duo",
    3: "YubiKey",
    4: "U2F",
    5: "记住设备",
    6: "组织 Duo",
    7: "WebAuthn 通行密钥",
    8: "恢复码",
  };
  const metas = payload.TwoFactorProviders2 || {};
  return payload.TwoFactorProviders.map((p) => {
    const id = Number(p);
    const meta = metas[p] || metas[id] || null;
    return {
      id,
      name: names[id] || "验证方式 " + id,
      emailHint: meta?.Email || null,
    };
  });
}
