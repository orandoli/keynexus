/**
 * 多格式提取与自定义 AI 提供商路由器单元测试：
 * 覆盖：
 *   1. 构造真实 ZIP-Deflate 的 Excel (.xlsx) 并验证共享字符串与单元格提取
 *   2. 构造真实 ZIP-Deflate 的 Word (.docx) 并验证段落与内嵌账号表格提取
 *   3. 构造 FlateDecode 压缩流 PDF 并验证文本层提取与扫描件自动分流
 *   4. 验证 OpenAI 兼容 / Google Gemini / Anthropic Claude / 自定义提供商（含自定义请求头与 exactEndpoint）路由
 *   5. 验证四态作用域自动推断（universal / web / desktop / mobile）与库内去重比对
 *
 * 跑法：node packages/importer-core/test/importer.test.mjs
 */

import zlib from "node:zlib";
import { parsePasswordFile, callAiProvider, fetchProviderModels } from "../src/index.js";

let pass = 0;
let fail = 0;
function ok(name, cond, extra) {
  if (cond) {
    pass++;
    console.log("  ok   " + name);
  } else {
    fail++;
    console.error("  FAIL " + name + (extra !== undefined ? "  " + JSON.stringify(extra) : ""));
  }
}

/** 构造合法的最小 ZIP (Deflate method=8) 供测试 .xlsx 与 .docx 解包 */
function buildMockZip(fileMap) {
  const te = new TextEncoder();
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  const entries = Object.entries(fileMap);

  for (const [name, content] of entries) {
    const nameBytes = te.encode(name);
    const rawBytes = typeof content === "string" ? te.encode(content) : content;
    const compBytes = zlib.deflateRawSync(rawBytes);

    const localHeader = Buffer.alloc(30 + nameBytes.length);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(8, 8); // deflate
    localHeader.writeUInt32LE(compBytes.length, 18);
    localHeader.writeUInt32LE(rawBytes.length, 22);
    localHeader.writeUInt16LE(nameBytes.length, 26);
    Buffer.from(nameBytes).copy(localHeader, 30);

    const centralHeader = Buffer.alloc(46 + nameBytes.length);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(8, 10);
    centralHeader.writeUInt32LE(compBytes.length, 20);
    centralHeader.writeUInt32LE(rawBytes.length, 24);
    centralHeader.writeUInt16LE(nameBytes.length, 28);
    centralHeader.writeUInt32LE(offset, 42);
    Buffer.from(nameBytes).copy(centralHeader, 46);

    localParts.push(localHeader, compBytes);
    centralParts.push(centralHeader);
    offset += localHeader.length + compBytes.length;
  }

  const cdBuf = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);

  return new Uint8Array(Buffer.concat([...localParts, cdBuf, eocd]));
}

console.log("[1] Excel (.xlsx) 本地解压与零 Token 表头直解 + 四态作用域推断");
{
  const xlsxBytes = buildMockZip({
    "xl/workbook.xml": `<workbook><sheets><sheet name="账号表" sheetId="1"/></sheets></workbook>`,
    "xl/sharedStrings.xml": `<sst><si><t>平台</t></si><si><t>账号</t></si><si><t>密码</t></si><si><t>微信</t></si><si><t>wx_orando</t></si><si><t>Wx#2026</t></si><si><t>Navicat数据库</t></si><si><t>root</t></si><si><t>Db!999</t></si></sst>`,
    "xl/worksheets/sheet1.xml": `<worksheet><sheetData>
      <row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c></row>
      <row r="2"><c r="A2" t="s"><v>3</v></c><c r="B2" t="s"><v>4</v></c><c r="C2" t="s"><v>5</v></c></row>
      <row r="3"><c r="A3" t="s"><v>6</v></c><c r="B3" t="s"><v>7</v></c><c r="C3" t="s"><v>8</v></c></row>
    </sheetData></worksheet>`,
  });

  const res = await parsePasswordFile({ name: "我的密码表.xlsx", bytes: xlsxBytes });
  ok("命中标准表头走 fast-rule 无需调 AI", res.mode === "fast-rule" && res.items.length === 2, res);
  ok("微信自动推断为 universal 并补齐三端 URI", res.items[0].pwdsvScope === "universal" && res.items[0].uris.includes("androidapp://com.tencent.mm"), res.items[0]);
  ok("Navicat 自动推断为 desktop 电脑端", res.items[1].pwdsvScope === "desktop", res.items[1]);
}

console.log("[2] Word (.docx) 段落与内嵌表格本地提取 + 自定义提供商 AI 解析");
{
  const docxBytes = buildMockZip({
    "word/document.xml": `<w:document><w:body>
      <w:p><w:r><w:t>部门交接密码备忘</w:t></w:r></w:p>
      <w:tbl>
        <w:tr><w:tc><w:p><w:r><w:t>招商手机银行</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>13800138000</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>Bank@888</w:t></w:r></w:p></w:tc></w:tr>
      </w:tbl>
    </w:body></w:document>`,
  });

  let capturedReq = null;
  const customProvider = {
    name: "我的自建网关",
    protocol: "openai-compatible",
    baseUrl: "https://my-gateway.example.com/custom/completions",
    exactEndpoint: true,
    apiKey: "sk-custom-123",
    customHeaders: { "X-Custom-Tenant": "orando" },
    textModel: "qwen-max-latest",
  };

  const res = await parsePasswordFile(
    { name: "入职交接.docx", bytes: docxBytes },
    {
      provider: customProvider,
      existingVaultItems: [{ id: "ex-1", name: "招商手机银行", username: "13800138000", password: "OldPassword" }],
      fetchImpl: async (url, init) => {
        capturedReq = { url, headers: init.headers, body: JSON.parse(init.body) };
        return {
          ok: true,
          status: 200,
          async text() {
            return JSON.stringify({
              choices: [{
                message: {
                  content: "```json\n" + JSON.stringify({
                    items: [{ name: "招商手机银行", username: "13800138000", password: "Bank@888", pwdsvScope: "mobile" }],
                  }) + "\n```",
                },
              }],
            });
          },
        };
      },
    },
  );

  ok("自定义提供商 exactEndpoint 与自定义请求头生效", capturedReq.url === "https://my-gateway.example.com/custom/completions" && capturedReq.headers["X-Custom-Tenant"] === "orando");
  ok("Word 表格内容已送入模型上下文", capturedReq.body.messages[1].content.includes("招商手机银行 | 13800138000 | Bank@888"));
  ok("手机银行标记为 mobile 且自动识别为覆盖更新已有条目", res.items[0].pwdsvScope === "mobile" && res.items[0].duplicateAction === "update" && res.items[0].existingId === "ex-1", res.items[0]);
}

console.log("[3] PDF 压缩文本流提取与图片拍照多模态 Gemini / Claude 协议验证");
{
  const compressedPdfStream = zlib.deflateSync(Buffer.from("BT (GitHub user: octocat pass: Gh#123456) Tj ET", "latin1"));
  const pdfPrefix = Buffer.from("%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode >>\nstream\n", "latin1");
  const pdfSuffix = Buffer.from("\nendstream\nendobj\n", "latin1");
  const pdfBytes = new Uint8Array(Buffer.concat([pdfPrefix, compressedPdfStream, pdfSuffix]));

  let geminiBody = null;
  const pdfRes = await parsePasswordFile(
    { name: "memo.pdf", bytes: pdfBytes },
    {
      provider: {
        name: "Gemini",
        protocol: "gemini",
        baseUrl: "https://generativelanguage.googleapis.com/v1beta",
        apiKey: "gm-key",
        textModel: "gemini-2.5-flash",
        visionModel: "gemini-2.5-flash",
      },
      fetchImpl: async (_url, init) => {
        geminiBody = JSON.parse(init.body);
        return {
          ok: true,
          status: 200,
          async text() {
            return JSON.stringify({
              candidates: [{ content: { parts: [{ text: JSON.stringify({ items: [{ name: "GitHub", username: "octocat", password: "Gh#123456" }] }) }] } }],
            });
          },
        };
      },
    },
  );
  ok("PDF FlateDecode 文本流成功解压并提取", geminiBody.contents[0].parts[0].text.includes("octocat") && pdfRes.items[0].pwdsvScope === "universal");

  // 测试手机拍照图片走 Claude Vision
  let claudeBody = null;
  await callAiProvider(
    {
      name: "Claude",
      protocol: "anthropic",
      baseUrl: "https://api.anthropic.com",
      apiKey: "ak-test",
      visionModel: "claude-3-5-sonnet-latest",
    },
    {
      userText: "提取照片密码",
      media: { mimeType: "image/jpeg", base64: "AAECAw==" },
    },
    {
      fetchImpl: async (_url, init) => {
        claudeBody = JSON.parse(init.body);
        return {
          ok: true,
          status: 200,
          async text() {
            return JSON.stringify({ content: [{ type: "text", text: '{"items":[]}' }] });
          },
        };
      },
    },
  );
  ok("图片拍照走 Anthropic Vision image 块格式正确", claudeBody.messages[0].content[0].type === "image" && claudeBody.messages[0].content[0].source.data === "AAECAw==");
}

console.log("[4] 模型源自动检测 (fetchProviderModels)");
{
  // OpenAI 兼容网关：/v1/models 404 时自动回退到 /models，并过滤 embedding 模型
  const oaiUrls = [];
  const oaiRes = await fetchProviderModels(
    { protocol: "openai-compatible", baseUrl: "http://152.32.234.200:8788/", apiKey: "sk-wb-test" },
    {
      fetchImpl: async (url, init) => {
        oaiUrls.push({ url, auth: init.headers.Authorization });
        if (url.endsWith("/v1/models")) {
          return { ok: false, status: 404, async text() { return "Not Found"; } };
        }
        return {
          ok: true,
          status: 200,
          async text() {
            return JSON.stringify({
              data: [
                { id: "text-embedding-3-large" },
                { id: "deepseek-chat" },
                { id: "gpt-4o-mini" },
              ],
            });
          },
        };
      },
    },
  );
  ok("OpenAI /v1/models 404 自动回退 /models", oaiUrls.length === 2 && oaiUrls[1].url === "http://152.32.234.200:8788/models");
  ok("OpenAI 携带 Bearer Auth", oaiUrls[1].auth === "Bearer sk-wb-test");
  ok("OpenAI 自动推荐非 embedding 文本模型与视觉模型", oaiRes.suggestedText === "deepseek-chat" && oaiRes.suggestedVision === "gpt-4o-mini", oaiRes);

  // Google Gemini 模型列表（自动剥离 models/ 前缀、携带 pageSize=1000 并过滤支持 generateContent 的模型）
  const gemRes = await fetchProviderModels(
    { protocol: "gemini", baseUrl: "https://generativelanguage.googleapis.com/v1beta", apiKey: "gm-k" },
    {
      fetchImpl: async (url, init) => {
        ok(
          "Gemini /v1beta/models?pageSize=1000 地址与头",
          url === "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1000" &&
            init.headers["x-goog-api-key"] === "gm-k",
        );
        return {
          ok: true,
          status: 200,
          async text() {
            return JSON.stringify({
              models: [
                { name: "models/embedding-001", supportedGenerationMethods: ["embedContent"] },
                { name: "models/gemini-2.5-flash", supportedGenerationMethods: ["generateContent"] },
              ],
            });
          },
        };
      },
    },
  );
  ok("Gemini 剥离 models/ 前缀并过滤非对话模型", gemRes.models.length === 1 && gemRes.suggestedText === "gemini-2.5-flash" && gemRes.suggestedVision === "gemini-2.5-flash", gemRes);

  // Anthropic 兼容子路径剥离 + 401 自动切换 Bearer 兜底（覆盖中转站如 wb-proxy）
  const antCalls = [];
  const antRes = await fetchProviderModels(
    { protocol: "anthropic", baseUrl: "https://relay.example.com/api/anthropic", apiKey: "sk-ant-secret" },
    {
      fetchImpl: async (url, init) => {
        antCalls.push({ url, xApiKey: init.headers["x-api-key"] || "", auth: init.headers.Authorization || "" });
        if (url === "https://relay.example.com/api/anthropic/v1/models" && init.headers["x-api-key"]) {
          return { ok: false, status: 401, async text() { return "unauthorized"; } };
        }
        if (url === "https://relay.example.com/api/anthropic/v1/models" && init.headers.Authorization) {
          return { ok: false, status: 404, async text() { return "<html>404</html>"; } };
        }
        if (url === "https://relay.example.com/api/anthropic/models") {
          return { ok: false, status: 404, async text() { return "Not Found"; } };
        }
        return {
          ok: true,
          status: 200,
          async text() {
            return JSON.stringify({ data: [{ id: "claude-3-7-sonnet-latest" }] });
          },
        };
      },
    },
  );
  ok(
    "Anthropic 401 自动 Bearer 兜底 + 剥离 /api/anthropic 后缀回退根 /v1/models",
    antCalls.some((c) => c.auth === "Bearer sk-ant-secret") && antRes.endpoint === "https://relay.example.com/v1/models",
    antCalls,
  );
  ok("Anthropic 返回推荐模型", antRes.suggestedText === "claude-3-7-sonnet-latest" && antRes.suggestedVision === "claude-3-7-sonnet-latest", antRes);

  // 智谱 /coding/paas/v4 版本段智能拼接 + models[].slug 解析
  let zhipuUrl = "";
  const zhipuRes = await fetchProviderModels(
    { protocol: "openai-compatible", baseUrl: "https://open.bigmodel.cn/api/coding/paas/v4", apiKey: "zp-key" },
    {
      fetchImpl: async (url) => {
        zhipuUrl = url;
        return {
          ok: true,
          status: 200,
          async text() {
            return JSON.stringify({ models: [{ slug: "glm-4.5" }, { slug: "glm-4v-plus" }] });
          },
        };
      },
    },
  );
  ok("非 v1 版本段直接拼 /models", zhipuUrl === "https://open.bigmodel.cn/api/coding/paas/v4/models", zhipuUrl);
  ok("解析 models[].slug 并推荐视觉模型", zhipuRes.suggestedText === "glm-4.5" && zhipuRes.suggestedVision === "glm-4v-plus", zhipuRes);

  // 错误返回中泄露 API Key 时自动脱敏
  let leakedErrMsg = "";
  try {
    await fetchProviderModels(
      { protocol: "openai-compatible", baseUrl: "https://bad.example.com", apiKey: "sk-topsecret-9999" },
      {
        fetchImpl: async () => ({
          ok: false,
          status: 500,
          async text() {
            return JSON.stringify({ error: { message: "bad token sk-topsecret-9999 rejected" } });
          },
        }),
      },
    );
  } catch (e) {
    leakedErrMsg = String(e.message || e);
  }
  ok("错误文本脱敏 API Key", !leakedErrMsg.includes("sk-topsecret-9999") && leakedErrMsg.includes("***"), leakedErrMsg);

  // callAiProvider 在 Anthropic 401 时自动切换 Bearer 兜底重试
  const msgAuthCalls = [];
  const msgReply = await callAiProvider(
    { protocol: "anthropic", baseUrl: "https://wb.example.com", apiKey: "sk-ant-bearer-only", textModel: "claude-sonnet-4-5" },
    { systemPrompt: "sys", userText: "hi" },
    {
      fetchImpl: async (_url, init) => {
        msgAuthCalls.push({ xApiKey: init.headers["x-api-key"] || "", auth: init.headers.Authorization || "" });
        if (init.headers["x-api-key"]) {
          return { ok: false, status: 401, async text() { return "use bearer"; } };
        }
        return {
          ok: true,
          status: 200,
          async text() {
            return JSON.stringify({ content: [{ type: "text", text: '{"ok":true}' }] });
          },
        };
      },
    },
  );
  ok(
    "callAiProvider Anthropic 401 自动 Bearer 重试成功",
    msgAuthCalls.length === 2 && msgAuthCalls[1].auth === "Bearer sk-ant-bearer-only" && msgReply === '{"ok":true}',
    msgAuthCalls,
  );

  // 传入自定义 fetchImpl 抛错时不误报浏览器 Mixed Content
  let customFetchErr = "";
  const prevWin = globalThis.window;
  try {
    globalThis.window = { location: { protocol: "https:" } };
    await fetchProviderModels(
      { protocol: "openai-compatible", baseUrl: "http://152.32.234.200:8788", apiKey: "sk-x" },
      {
        fetchImpl: async () => {
          throw new Error("relay unreachable");
        },
      },
    );
  } catch (e) {
    customFetchErr = String(e.message || e);
  } finally {
    if (prevWin === undefined) delete globalThis.window;
    else globalThis.window = prevWin;
  }
  ok(
    "自定义 fetchImpl 抛错不误报 Mixed Content",
    customFetchErr.includes("relay unreachable") && !customFetchErr.includes("浏览器安全策略拦截"),
    customFetchErr,
  );

  // DSH / 网关对象映射格式 { models: { id: { name, inputModalities } } } 解析
  const mapRes = await fetchProviderModels(
    { protocol: "anthropic", baseUrl: "http://152.32.234.200:8788/", apiKey: "sk-map" },
    {
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            models: {
              "deepseek-v4.1-flash": { name: "DeepSeek-V4.1-Flash", inputModalities: ["text", "image"] },
              "glm-5.3": { name: "GLM-5.3" },
            },
          });
        },
      }),
    },
  );
  ok(
    "支持 DSH models 对象映射格式并保留名称与模态",
    mapRes.models.length === 2 &&
      mapRes.suggestedVision === "deepseek-v4.1-flash" &&
      mapRes.modelDetails.find((m) => m.id === "deepseek-v4.1-flash")?.name === "DeepSeek-V4.1-Flash",
    mapRes,
  );
}

console.log("");
console.log(pass + " 通过, " + fail + " 失败");
process.exit(fail === 0 ? 0 : 1);
