/**
 * 可自由更换 & 自定义的 AI 模型提供商直连路由器（100% 客户端发起，不经过 PWDSV 服务器）。
 *
 * 支持三大底层协议：
 *   1. "openai-compatible"：OpenAI / DeepSeek / 通义千问 / Kimi / 智谱 / 硅基流动 / OpenRouter / 本地 Ollama / 任意自建 NewAPI·OneAPI·AxonHub
 *   2. "gemini"           ：Google Gemini 原生 generateContent 协议（原生支持图片与 PDF inlineData）
 *   3. "anthropic"        ：Anthropic Claude Messages 协议
 */

export const PRESET_PROVIDERS = Object.freeze([
  {
    id: "deepseek",
    name: "DeepSeek (官方)",
    protocol: "openai-compatible",
    baseUrl: "https://api.deepseek.com/v1",
    textModel: "deepseek-chat",
    visionModel: "",
    requiresKey: true,
  },
  {
    id: "qwen",
    name: "通义千问 (阿里云百炼)",
    protocol: "openai-compatible",
    baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1",
    textModel: "qwen-plus",
    visionModel: "qwen-vl-max",
    requiresKey: true,
  },
  {
    id: "gemini",
    name: "Google Gemini",
    protocol: "gemini",
    baseUrl: "https://generativelanguage.googleapis.com/v1beta",
    textModel: "gemini-2.5-flash",
    visionModel: "gemini-2.5-flash",
    requiresKey: true,
  },
  {
    id: "openai",
    name: "OpenAI",
    protocol: "openai-compatible",
    baseUrl: "https://api.openai.com/v1",
    textModel: "gpt-4o-mini",
    visionModel: "gpt-4o-mini",
    requiresKey: true,
  },
  {
    id: "anthropic",
    name: "Anthropic Claude",
    protocol: "anthropic",
    baseUrl: "https://api.anthropic.com/v1",
    textModel: "claude-3-5-sonnet-latest",
    visionModel: "claude-3-5-sonnet-latest",
    requiresKey: true,
  },
  {
    id: "siliconflow",
    name: "硅基流动 (SiliconFlow)",
    protocol: "openai-compatible",
    baseUrl: "https://api.siliconflow.cn/v1",
    textModel: "Qwen/Qwen2.5-72B-Instruct",
    visionModel: "Qwen/Qwen2.5-VL-72B-Instruct",
    requiresKey: true,
  },
  {
    id: "moonshot",
    name: "Kimi (Moonshot)",
    protocol: "openai-compatible",
    baseUrl: "https://api.moonshot.cn/v1",
    textModel: "moonshot-v1-8k",
    visionModel: "moonshot-v1-8k-vision-preview",
    requiresKey: true,
  },
  {
    id: "ollama",
    name: "本地 Ollama (离线不出内网)",
    protocol: "openai-compatible",
    baseUrl: "http://127.0.0.1:11434/v1",
    textModel: "qwen2.5:7b",
    visionModel: "qwen2.5vl:7b",
    requiresKey: false,
  },
]);

export const EXTRACTION_SYSTEM_PROMPT = `你是一个严谨的本地密码归整助手。请从用户提供的文档、表格或图片内容中提取所有账号密码信息，并严格只输出合法的 JSON 对象（不要输出任何解释文字或 Markdown 代码块包裹）。

输出 JSON 结构必须严格如下：
{
  "items": [
    {
      "name": "服务或软件名称（如 GitHub / 微信 / 公司VPN / 招商银行）",
      "username": "登录账号、邮箱、手机号或用户名（没有则填空字符串）",
      "password": "密码、口令或 PIN（原样精确保留大小写与特殊字符）",
      "totp": "两步验证密钥（没有则填空字符串）",
      "uris": [
        "关联网址或应用标识：网站用 https://域名；Windows桌面软件用 app://进程名.exe；安卓App用 androidapp://包名"
      ],
      "pwdsvScope": "四选一：universal（网页/电脑/手机多端通用账号）| web（仅网页端）| desktop（仅电脑客户端）| mobile（仅手机端）",
      "folderName": "建议分类文件夹名（如 工作 / 开发 / 金融 / 社交，不确定填空字符串）",
      "notes": "其他附加信息（如端口、安全问题、备注）",
      "confidence": 0.95
    }
  ]
}

规则：
1. 绝对不要编造原文中没有的密码，字符必须逐字准确（注意区分 0/O、1/l/I）。
2. 如果某个知名平台（如微信、QQ、飞书、钉钉、GitHub、Google、微软、B站、Steam、Telegram）通常多端共用同一套账号密码，且文中未限定仅某端专用，请将 pwdsvScope 设为 "universal"。
3. 如果明确是数据库工具、SSH、远程桌面、电脑单机软件，pwdsvScope 设为 "desktop"；如果明确是手机 App 专用或手机银行密码，设为 "mobile"；纯网页后台设为 "web"。`;

function parseCustomHeaders(rawHeaders) {
  if (!rawHeaders) return {};
  if (typeof rawHeaders === "object" && !Array.isArray(rawHeaders)) {
    return Object.fromEntries(Object.entries(rawHeaders).map(([k, v]) => [String(k), String(v)]));
  }
  if (typeof rawHeaders === "string" && rawHeaders.trim()) {
    try {
      return parseCustomHeaders(JSON.parse(rawHeaders));
    } catch {
      return {};
    }
  }
  return {};
}

function buildOpenAiEndpoint(baseUrl, exactEndpoint = false) {
  const clean = String(baseUrl || "").trim().replace(/\/+$/, "");
  if (!clean) throw new Error("提供商 Base URL 不能为空");
  if (exactEndpoint || /\/chat\/completions$/i.test(clean)) return clean;
  if (/\/v\d+$/i.test(clean) || /\/compatible-mode\/v\d+$/i.test(clean)) {
    return clean + "/chat/completions";
  }
  return clean + "/v1/chat/completions";
}

function buildAnthropicEndpoint(baseUrl, exactEndpoint = false) {
  const clean = String(baseUrl || "").trim().replace(/\/+$/, "");
  if (!clean) throw new Error("提供商 Base URL 不能为空");
  if (exactEndpoint || /\/messages$/i.test(clean)) return clean;
  if (/\/v\d+$/i.test(clean)) return clean + "/messages";
  return clean + "/v1/messages";
}

function buildGeminiEndpoint(baseUrl, model, exactEndpoint = false) {
  const clean = String(baseUrl || "").trim().replace(/\/+$/, "");
  if (!clean) throw new Error("提供商 Base URL 不能为空");
  if (exactEndpoint || /:generateContent$/i.test(clean)) return clean;
  const baseWithVer = /\/v1(?:beta)?$/i.test(clean) ? clean : clean + "/v1beta";
  const m = String(model || "gemini-2.5-flash").replace(/^models\//, "");
  return `${baseWithVer}/models/${encodeURIComponent(m)}:generateContent`;
}

/**
 * 调用任意已配置的 AI 模型提供商执行提取请求
 * @param {object} provider 提供商配置（预设或自定义）
 * @param {{ userText?: string, media?: { mimeType: string, base64: string }, systemPrompt?: string }} input
 * @param {{ fetchImpl?: typeof fetch }} [opts]
 * @returns {Promise<string>} 模型返回的原始文本
 */
export async function callAiProvider(provider, input, opts = {}) {
  const fetchFn = opts.fetchImpl || ((...args) => fetch(...args));
  const protocol = provider?.protocol || "openai-compatible";
  const apiKey = String(provider?.apiKey || "").trim();
  const extraHeaders = parseCustomHeaders(provider?.customHeaders);
  const hasMedia = Boolean(input?.media?.base64);

  const model = hasMedia
    ? (provider?.visionModel || provider?.textModel || "").trim()
    : (provider?.textModel || provider?.visionModel || "").trim();

  if (!model) {
    throw new Error(hasMedia
      ? "当前提供商未配置视觉模型（Vision Model），无法直接识别图片/扫描件，请在模型设置中补充视觉模型名称"
      : "当前提供商未配置模型名称（Model ID）");
  }

  const sys = input.systemPrompt ?? EXTRACTION_SYSTEM_PROMPT;
  const promptText = input.userText || "请识别并提取其中的所有账号密码信息，输出统一 JSON。";

  let url;
  let headers = { "Content-Type": "application/json", ...extraHeaders };
  let bodyObj;

  if (protocol === "gemini") {
    if (hasMedia && !provider?.visionModel && !/gemini/i.test(model)) {
      throw new Error("请配置支持多模态的 Gemini 模型名称");
    }
    url = buildGeminiEndpoint(provider.baseUrl, model, Boolean(provider.exactEndpoint));
    if (apiKey) headers["x-goog-api-key"] = apiKey;

    const parts = [{ text: promptText }];
    if (hasMedia) {
      parts.push({
        inlineData: {
          mimeType: input.media.mimeType || "image/jpeg",
          data: input.media.base64,
        },
      });
    }
    bodyObj = {
      systemInstruction: { parts: [{ text: sys }] },
      contents: [{ role: "user", parts }],
      generationConfig: {
        temperature: 0.1,
        responseMimeType: "application/json",
      },
    };
  } else if (protocol === "anthropic") {
    if (hasMedia && input.media.mimeType === "application/pdf") {
      // Claude document block or fallback prompt
    }
    url = buildAnthropicEndpoint(provider.baseUrl, Boolean(provider.exactEndpoint));
    if (apiKey) headers["x-api-key"] = apiKey;
    headers["anthropic-version"] = headers["anthropic-version"] || "2023-06-01";

    const content = [];
    if (hasMedia) {
      const blockType = input.media.mimeType === "application/pdf" ? "document" : "image";
      content.push({
        type: blockType,
        source: {
          type: "base64",
          media_type: input.media.mimeType || "image/jpeg",
          data: input.media.base64,
        },
      });
    }
    content.push({ type: "text", text: promptText });

    bodyObj = {
      model,
      max_tokens: 4096,
      temperature: 0.1,
      system: sys,
      messages: [{ role: "user", content }],
    };
  } else {
    // 默认：openai-compatible（兼容绝大多数国内外大模型、中转站与本地 Ollama）
    if (hasMedia && input.media.mimeType === "application/pdf") {
      throw new Error("当前扫描版 PDF 没有文本层；OpenAI 兼容接口仅接收图片，请将扫描页截图上传或切换为 Google Gemini / Claude 提供商直接识读扫描版 PDF");
    }
    if (hasMedia && !provider?.visionModel) {
      throw new Error(`提供商「${provider?.name || "当前模型"}」未填写视觉模型（Vision Model），无法识别图片`);
    }
    url = buildOpenAiEndpoint(provider.baseUrl, Boolean(provider.exactEndpoint));
    if (apiKey) headers.Authorization = "Bearer " + apiKey;

    const userContent = hasMedia
      ? [
          { type: "text", text: promptText },
          {
            type: "image_url",
            image_url: {
              url: `data:${input.media.mimeType || "image/jpeg"};base64,${input.media.base64}`,
            },
          },
        ]
      : promptText;

    bodyObj = {
      model,
      temperature: 0.1,
      messages: [
        { role: "system", content: sys },
        { role: "user", content: userContent },
      ],
    };
  }

  let res;
  const payloadStr = JSON.stringify(bodyObj);
  try {
    res = await fetchFn(url, {
      method: "POST",
      headers,
      body: payloadStr,
    });
  } catch (e) {
    throw new Error(`连接模型提供商失败 (${url})：${e?.message || e}`);
  }

  if ((res.status === 401 || res.status === 403) && apiKey) {
    let retryHeaders = null;
    if (protocol === "anthropic" && headers["x-api-key"] && !headers.Authorization) {
      retryHeaders = { ...headers, Authorization: "Bearer " + apiKey };
      delete retryHeaders["x-api-key"];
    } else if (protocol === "openai-compatible" && headers.Authorization && !headers["x-api-key"]) {
      retryHeaders = { ...headers, "x-api-key": apiKey };
      delete retryHeaders.Authorization;
    }
    if (retryHeaders) {
      try {
        const retryRes = await fetchFn(url, {
          method: "POST",
          headers: retryHeaders,
          body: payloadStr,
        });
        if (retryRes.ok || (retryRes.status !== 401 && retryRes.status !== 403)) {
          res = retryRes;
        }
      } catch {
        // Ignore retry transport failure and preserve primary 401/403 error handling.
      }
    }
  }

  const rawText = await res.text();
  let json = null;
  try {
    json = JSON.parse(rawText);
  } catch {
    json = null;
  }

  if (!res.ok) {
    const errMsg =
      json?.error?.message ||
      json?.message ||
      (typeof json?.error === "string" && json.error) ||
      rawText.slice(0, 220) ||
      `HTTP ${res.status}`;
    throw new Error(`模型接口报错 (${res.status})：${errMsg}`);
  }

  if (protocol === "gemini") {
    const text = json?.candidates?.[0]?.content?.parts?.map((p) => p?.text || "").join("") || "";
    if (!text) throw new Error("Gemini 返回内容为空");
    return text;
  }

  if (protocol === "anthropic") {
    const text = (json?.content || [])
      .filter((b) => b?.type === "text")
      .map((b) => b.text)
      .join("");
    if (!text) throw new Error("Claude 返回内容为空");
    return text;
  }

  const text = json?.choices?.[0]?.message?.content || "";
  if (!text) throw new Error("模型返回内容为空，请检查 Base URL 与模型名称是否匹配");
  return text;
}

/** 一键测试模型提供商连通性 */
export async function testProviderConnection(provider, opts = {}) {
  const reply = await callAiProvider(
    provider,
    {
      systemPrompt: '只输出 JSON：{"ok":true}',
      userText: '请返回 {"ok":true}',
    },
    opts,
  );
  return { ok: true, sample: reply.slice(0, 120) };
}

function isVisionModelId(id) {
  return /(?:vl|vision|gpt-4o|gpt-4\.1|gpt-5|gemini|claude-[34]|sonnet|opus|haiku|pixtral|llava|glm-[45]v|minicpm-v|(?:^|[-_/])o[134](?:$|[-_/]))/i.test(
    String(id || ""),
  );
}

function isAuxNonChatModelId(id) {
  return /(?:embedding|embed|whisper|tts|dall-e|moderation|rerank|bge-|text-embedding)/i.test(String(id || ""));
}

/** 常见 Anthropic / 编程套餐兼容子路径后缀（按长度降序优先匹配） */
const KNOWN_COMPAT_SUFFIXES = [
  "/api/claudecode",
  "/api/anthropic",
  "/apps/anthropic",
  "/api/coding",
  "/claudecode",
  "/anthropic",
  "/step_plan",
  "/coding",
  "/claude",
];

function stripCompatSuffix(url) {
  const lower = url.toLowerCase();
  for (const suffix of KNOWN_COMPAT_SUFFIXES) {
    if (lower.endsWith(suffix)) {
      return url.slice(0, url.length - suffix.length);
    }
  }
  return null;
}

function endsWithVersionSegment(url) {
  const last = url.split("/").pop() || "";
  return /^v\d+$/i.test(last);
}

function redactSecret(text, secrets = []) {
  let s = String(text || "").trim();
  if (!s || s.startsWith("<")) return "";
  for (const sec of secrets) {
    const token = String(sec || "").trim();
    if (token.length >= 4 && s.includes(token)) {
      s = s.split(token).join("***");
    }
  }
  return s.length > 260 ? s.slice(0, 260) + "…" : s;
}

function buildModelsEndpoints(protocol, baseUrl, exactEndpoint = false) {
  const clean = String(baseUrl || "").trim().replace(/\/+$/, "");
  if (!clean) throw new Error("提供商 Base URL 不能为空");

  if (protocol === "gemini") {
    const base = clean
      .replace(/\/models\/[^/]+:generateContent$/i, "")
      .replace(/:generateContent$/i, "")
      .replace(/\/models$/i, "")
      .replace(/\/v1(?:beta)?$/i, "");
    return [`${base}/v1beta/models?pageSize=1000`];
  }

  if (exactEndpoint) {
    const verMatch = clean.match(/^(https?:\/\/.+?\/v\d+)\//i);
    if (verMatch) return [`${verMatch[1]}/models`];
    const slashIdx = clean.lastIndexOf("/");
    const schemeIdx = clean.indexOf("://");
    if (slashIdx > (schemeIdx >= 0 ? schemeIdx + 3 : 0)) {
      return [`${clean.slice(0, slashIdx)}/v1/models`];
    }
  }

  const base = clean
    .replace(/\/chat\/completions$/i, "")
    .replace(/\/completions$/i, "")
    .replace(/\/messages$/i, "")
    .replace(/\/models$/i, "");

  const candidates = [];
  if (/\/v1$/i.test(base) || /\/compatible-mode\/v\d+$/i.test(base)) {
    candidates.push(`${base}/models`);
  } else if (endsWithVersionSegment(base)) {
    candidates.push(`${base}/models`, `${base}/v1/models`);
  } else {
    candidates.push(`${base}/v1/models`, `${base}/models`);
  }

  const stripped = stripCompatSuffix(base);
  if (stripped) {
    candidates.push(`${stripped}/v1/models`, `${stripped}/models`);
  }

  if (protocol !== "anthropic") {
    candidates.push(`${base}/api/tags`);
  }

  return Array.from(new Set(candidates));
}

function buildDetectHeaders(protocol, authMode, apiKey, extraHeaders) {
  const headers = { Accept: "application/json", ...extraHeaders };
  if (protocol === "anthropic") {
    headers["anthropic-version"] = headers["anthropic-version"] || "2023-06-01";
  }
  if (apiKey) {
    if (authMode === "x-goog-api-key") {
      headers["x-goog-api-key"] = apiKey;
    } else if (authMode === "x-api-key") {
      headers["x-api-key"] = apiKey;
    } else {
      headers.Authorization = "Bearer " + apiKey;
    }
  }
  return headers;
}

function normalizeDiscoveredModalities(raw, id) {
  const arr = Array.isArray(raw?.inputModalities)
    ? raw.inputModalities
    : Array.isArray(raw?.input)
      ? raw.input
      : null;
  if (arr) {
    const cleaned = Array.from(new Set(arr.map((x) => String(x || "").toLowerCase()).filter((x) => x === "text" || x === "image")));
    if (cleaned.length) return cleaned;
  }
  return isVisionModelId(id) ? ["text", "image"] : ["text"];
}

function extractModelDetails(json, protocol) {
  const byId = new Map();
  const pushRow = (rawId, rawObj) => {
    const id = String(rawId || "").replace(/^models\//, "").trim();
    if (!id) return;
    if (byId.has(id)) return;
    const rawName = typeof rawObj?.displayName === "string"
      ? rawObj.displayName
      : typeof rawObj?.name === "string"
        ? rawObj.name
        : "";
    const cleanName = rawName.replace(/^models\//, "").trim();
    byId.set(id, {
      id,
      name: cleanName && cleanName !== id ? cleanName : "",
      inputModalities: normalizeDiscoveredModalities(rawObj, id),
    });
  };

  if (Array.isArray(json)) {
    for (const m of json) {
      if (typeof m === "string") pushRow(m, null);
      else pushRow(m?.slug || m?.id || m?.name || m?.model, m);
    }
  } else if (Array.isArray(json?.data)) {
    for (const m of json.data) {
      if (typeof m === "string") pushRow(m, null);
      else pushRow(m?.id || m?.slug || m?.name, m);
    }
  } else if (Array.isArray(json?.models)) {
    for (const m of json.models) {
      if (protocol === "gemini" && Array.isArray(m?.supportedGenerationMethods) && !m.supportedGenerationMethods.includes("generateContent")) {
        continue;
      }
      if (typeof m === "string") pushRow(m, null);
      else if (protocol === "gemini") pushRow(m?.name || m?.slug || m?.id, m);
      else pushRow(m?.slug || m?.id || m?.name || m?.model, m);
    }
  } else if (json?.models && typeof json.models === "object" && !Array.isArray(json.models)) {
    for (const [key, val] of Object.entries(json.models)) {
      if (!val || typeof val !== "object" || Array.isArray(val)) continue;
      pushRow(String(key || "").trim() || val.id || val.slug || val.name, val);
    }
  }

  return Array.from(byId.values()).sort((a, b) => a.id.localeCompare(b.id));
}

/**
 * 自动探测模型提供商的可用模型列表，并智能推荐文本/视觉模型 ID。
 * 借鉴 cc-switch 实战策略：兼容子路径剥离、版本段智能拼接、Gemini pageSize=1000、
 * models[].slug、401/403 鉴权头互为兜底重试与错误信息密钥脱敏。
 */
export async function fetchProviderModels(provider, opts = {}) {
  const fetchFn = opts.fetchImpl || ((...args) => fetch(...args));
  const protocol = provider?.protocol || "openai-compatible";
  const apiKey = String(provider?.apiKey || "").trim();
  const extraHeaders = parseCustomHeaders(provider?.customHeaders);
  const secrets = [apiKey, ...Object.values(extraHeaders)];

  const primaryAuth =
    protocol === "gemini" ? "x-goog-api-key" : protocol === "anthropic" ? "x-api-key" : "bearer";
  const fallbackAuth =
    apiKey && protocol === "anthropic"
      ? "bearer"
      : apiKey && protocol === "openai-compatible"
        ? "x-api-key"
        : "";

  const endpoints = buildModelsEndpoints(protocol, provider?.baseUrl, Boolean(provider?.exactEndpoint));
  let lastErr = null;

  async function requestModels(endpoint, authMode) {
    const headers = buildDetectHeaders(protocol, authMode, apiKey, extraHeaders);
    let res;
    try {
      res = await fetchFn(endpoint, { method: "GET", headers });
    } catch (e) {
      if (
        !opts.fetchImpl &&
        typeof window !== "undefined" &&
        window.location?.protocol === "https:" &&
        /^http:\/\//i.test(endpoint)
      ) {
        throw new Error(
          `浏览器安全策略拦截了 HTTPS 页面直接请求 HTTP 地址 (${endpoint})，请改用 HTTPS 地址或同源反向代理（如 /ai-proxy/8788）`,
        );
      }
      throw new Error(`连接模型列表接口失败 (${endpoint})：${redactSecret(e?.message || e, secrets)}`);
    }

    const rawText = await res.text();
    let json = null;
    try {
      json = JSON.parse(rawText);
    } catch {
      json = null;
    }

    if (!res.ok) {
      const rawErr =
        json?.error?.message ||
        json?.message ||
        (typeof json?.error === "string" && json.error) ||
        redactSecret(rawText, secrets);
      const cleanErr = redactSecret(rawErr, secrets) || `HTTP ${res.status}`;
      return { ok: false, status: res.status, message: `获取模型列表失败 (${res.status})：${cleanErr}` };
    }

    const modelDetails = extractModelDetails(json, protocol);
    const models = modelDetails.map((m) => m.id);
    return { ok: true, status: res.status, models, modelDetails };
  }

  for (let i = 0; i < endpoints.length; i++) {
    const endpoint = endpoints[i];
    let outcome = await requestModels(endpoint, primaryAuth);

    if (!outcome.ok && (outcome.status === 401 || outcome.status === 403) && fallbackAuth) {
      const retryOutcome = await requestModels(endpoint, fallbackAuth);
      if (retryOutcome.ok || (retryOutcome.status !== 401 && retryOutcome.status !== 403)) {
        outcome = retryOutcome;
      }
    }

    if (!outcome.ok) {
      lastErr = new Error(outcome.message);
      if ((outcome.status === 404 || outcome.status === 405) && i < endpoints.length - 1) {
        continue;
      }
      throw lastErr;
    }

    if (outcome.models.length) {
      const suggestedText = outcome.models.find((id) => !isAuxNonChatModelId(id)) || outcome.models[0];
      const suggestedVision =
        outcome.modelDetails?.find(
          (m) => !isAuxNonChatModelId(m.id) && (m.inputModalities?.includes("image") || isVisionModelId(m.id)),
        )?.id || "";
      return {
        models: outcome.models,
        modelDetails: outcome.modelDetails || [],
        suggestedText,
        suggestedVision,
        endpoint,
      };
    }
    lastErr = new Error("接口连通成功，但未返回任何可用模型");
  }

  throw lastErr || new Error("未检测到可用模型");
}
