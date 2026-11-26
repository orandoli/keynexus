/**
 * PWDSV 跨端多格式文件识别与 AI 密码解析统一入口。
 *
 * 工作流：
 *   任意文件 / 拍照截图 -> extractFilePayload 本地提取 ->
 *   (若命中标准密码表且 forceAi !== true 则直接秒出；否则分块直连用户所选 AI 提供商) ->
 *   normalizeAndCompareRecords 统一成四态作用域标准格式并与现有密码库比对去重
 */

import { extractFilePayload, bytesToBase64 } from "./extractors.js";
import { PRESET_PROVIDERS, callAiProvider, testProviderConnection, fetchProviderModels } from "./providers.js";
import { extractJsonFromModelOutput, normalizeAndCompareRecords, normalizeSingleRecord } from "./normalizer.js";

export {
  PRESET_PROVIDERS,
  extractFilePayload,
  bytesToBase64,
  callAiProvider,
  testProviderConnection,
  fetchProviderModels,
  extractJsonFromModelOutput,
  normalizeAndCompareRecords,
  normalizeSingleRecord,
};

/** 将超长文档按行切分为安全长度块，防止超出单次模型上下文 */
function splitTextIntoChunks(text, maxChars = 12000) {
  const clean = String(text || "").trim();
  if (!clean) return [];
  if (clean.length <= maxChars) return [clean];

  const lines = clean.split(/\r?\n/);
  const chunks = [];
  let buf = "";
  for (const line of lines) {
    if (buf.length + line.length + 1 > maxChars && buf.length > 0) {
      chunks.push(buf);
      buf = line;
    } else {
      buf = buf ? buf + "\n" + line : line;
    }
  }
  if (buf) chunks.push(buf);
  return chunks;
}

/**
 * 解析单个文件并返回可直接展示在「预览核对表格」的统一密码记录数组
 * @param {{ name: string, mimeType?: string, bytes: Uint8Array|ArrayBuffer }} file
 * @param {{
 *   provider?: object,
 *   existingVaultItems?: Array,
 *   forceAi?: boolean,
 *   fetchImpl?: typeof fetch,
 *   onProgress?: (statusText: string) => void,
 * }} [opts]
 */
export async function parsePasswordFile(file, opts = {}) {
  const onProgress = opts.onProgress || (() => {});
  onProgress(`正在本地读取文件：${file.name}…`);

  const extracted = await extractFilePayload(file);

  // 1. 标准 CSV / XLSX / Bitwarden JSON 快筛通道（除非用户强制走 AI 深度语义识别）
  if (extracted.fastItems?.length && !opts.forceAi) {
    onProgress(`已命中标准表格列，零 Token 快速识别出 ${extracted.fastItems.length} 条记录`);
    return {
      mode: "fast-rule",
      fileName: extracted.fileName,
      items: normalizeAndCompareRecords(extracted.fastItems, opts.existingVaultItems, extracted.fileName),
    };
  }

  // 2. 需要调用 AI 模型（非标表格、Word、PDF、杂乱 TXT 备忘录、图片/拍照）
  if (!opts.provider) {
    throw new Error("此文件需要调用 AI 模型进行智能解析，请先配置并选择一个 AI 模型提供商");
  }

  if (extracted.kind === "image" || extracted.kind === "pdf-visual") {
    onProgress(`正在调用 ${opts.provider.name || "AI 视觉模型"} 识别画面中的账号密码…`);
    const modelReply = await callAiProvider(
      opts.provider,
      {
        userText: `文件名：${extracted.fileName}\n请仔细识别画面中的所有平台/应用名称、账号、密码、网址及适用端，输出统一 JSON。`,
        media: { mimeType: extracted.mimeType, base64: extracted.base64 },
      },
      { fetchImpl: opts.fetchImpl },
    );
    const parsedJson = extractJsonFromModelOutput(modelReply);
    return {
      mode: "ai-vision",
      fileName: extracted.fileName,
      items: normalizeAndCompareRecords(parsedJson, opts.existingVaultItems, extracted.fileName),
    };
  }

  const chunks = splitTextIntoChunks(extracted.text, 12000);
  if (!chunks.length) {
    throw new Error("文件内容为空或未提取到可识别文本");
  }

  const mergedRaw = [];
  for (let i = 0; i < chunks.length; i++) {
    onProgress(
      chunks.length > 1
        ? `正在调用 ${opts.provider.name || "AI 模型"} 解析第 ${i + 1}/${chunks.length} 段内容…`
        : `正在调用 ${opts.provider.name || "AI 模型"} 解析文档内容…`,
    );
    const modelReply = await callAiProvider(
      opts.provider,
      {
        userText: `来源文件：${extracted.fileName}\n\n以下是需要提取账号密码的原文内容：\n----------------\n${chunks[i]}\n----------------`,
      },
      { fetchImpl: opts.fetchImpl },
    );
    const parsedJson = extractJsonFromModelOutput(modelReply);
    const arr = Array.isArray(parsedJson) ? parsedJson : parsedJson?.items || [];
    mergedRaw.push(...arr);
  }

  return {
    mode: "ai-text",
    fileName: extracted.fileName,
    items: normalizeAndCompareRecords(mergedRaw, opts.existingVaultItems, extracted.fileName),
  };
}
