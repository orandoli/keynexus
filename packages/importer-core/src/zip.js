/**
 * 零依赖轻量 ZIP 解包器（基于标准 Web API DataView + DecompressionStream("deflate-raw")）。
 * 同时兼容 Node.js 20+、Windows WebView2、Chrome/Edge 扩展与 Android WebView，
 * 用于在客户端本地内存中直接读取 .xlsx 与 .docx 内部 XML，无需上传文件到任何服务器。
 */

const TD = new TextDecoder("utf-8", { fatal: false });

async function inflateRaw(compressed) {
  const ds = new DecompressionStream("deflate-raw");
  const writer = ds.writable.getWriter();
  writer.write(compressed);
  writer.close();
  const out = [];
  const reader = ds.readable.getReader();
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) out.push(value);
  }
  const total = out.reduce((n, b) => n + b.byteLength, 0);
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of out) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}

/**
 * 解析 ZIP 字节流并返回文件名 -> Uint8Array 映射表
 * @param {Uint8Array|ArrayBuffer} input
 * @returns {Promise<Map<string, Uint8Array>>}
 */
export async function unzipEntries(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  // 从尾部向前寻找 End of Central Directory (0x06054b50)
  let eocdOffset = -1;
  const minSearch = Math.max(0, bytes.length - 65557);
  for (let i = bytes.length - 22; i >= minSearch; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) {
    throw new Error("无法识别的压缩文档格式（缺少 ZIP 目录尾标识）");
  }

  const totalEntries = view.getUint16(eocdOffset + 10, true);
  const cdOffset = view.getUint32(eocdOffset + 16, true);

  const files = new Map();
  let ptr = cdOffset;
  for (let idx = 0; idx < totalEntries && ptr + 46 <= bytes.length; idx++) {
    if (view.getUint32(ptr, true) !== 0x02014b50) break;
    const method = view.getUint16(ptr + 10, true);
    const compSize = view.getUint32(ptr + 20, true);
    const nameLen = view.getUint16(ptr + 28, true);
    const extraLen = view.getUint16(ptr + 30, true);
    const commentLen = view.getUint16(ptr + 32, true);
    const localHeaderOffset = view.getUint32(ptr + 42, true);

    const name = TD.decode(bytes.subarray(ptr + 46, ptr + 46 + nameLen));
    ptr += 46 + nameLen + extraLen + commentLen;

    if (name.endsWith("/") || localHeaderOffset + 30 > bytes.length) continue;
    if (view.getUint32(localHeaderOffset, true) !== 0x04034b50) continue;

    const localNameLen = view.getUint16(localHeaderOffset + 26, true);
    const localExtraLen = view.getUint16(localHeaderOffset + 28, true);
    const dataStart = localHeaderOffset + 30 + localNameLen + localExtraLen;
    const rawSlice = bytes.subarray(dataStart, dataStart + compSize);

    if (method === 0) {
      files.set(name, rawSlice);
    } else if (method === 8) {
      files.set(name, await inflateRaw(rawSlice));
    }
  }
  return files;
}

export function decodeUtf8(bytes) {
  return bytes ? TD.decode(bytes) : "";
}
