/**
 * 多格式本地密码文件提取器（100% 本地内存执行，不上传原始文件到服务器）：
 * 支持：
 * 1. CSV / TSV / JSON（含主流浏览器直接结构化快筛，免调 AI；非标表头自动转文本送 AI）
 * 2. Excel (.xlsx)（解析多工作表与共享字符串表）
 * 3. Word (.docx)（解析正文段落与内嵌账号表格）
 * 4. PDF (.pdf)（解析 FlateDecode 文本流与 UTF-16BE 中文文本；若是扫描件自动标记转视觉模型）
 * 5. 纯文本 / Markdown (.txt / .md / .log / .ini / .yaml / .xml)
 * 6. 图片 / 拍照 (.png / .jpg / .jpeg / .webp / .bmp)
 */

import { unzipEntries, decodeUtf8 } from "./zip.js";

const TD_UTF8 = new TextDecoder("utf-8", { fatal: false });

function decodeEntities(xml) {
  return String(xml || "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)));
}

export function bytesToBase64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < u8.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

/* ---------------------------------------------------------------- CSV 解析 */

export function parseDelimitedRows(text, delimiter = ",") {
  const rows = [];
  let row = [];
  let cell = "";
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"' && text[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (ch === '"') {
        inQuotes = false;
      } else {
        cell += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === delimiter) {
      row.push(cell.trim());
      cell = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(cell.trim());
      if (row.some((c) => c !== "")) rows.push(row);
      row = [];
      cell = "";
    } else {
      cell += ch;
    }
  }
  if (cell.length || row.length) {
    row.push(cell.trim());
    if (row.some((c) => c !== "")) rows.push(row);
  }
  return rows;
}

/** 尝试直接按标准密码导出表头（Chrome / Edge / Bitwarden / 1Password / 中文常见表头）零 AI 解析 */
export function tryFastParseTabular(rows, sourceName = "") {
  if (!Array.isArray(rows) || rows.length < 2) return null;
  const header = rows[0].map((h) => String(h || "").trim().toLowerCase().replace(/^\ufeff/, ""));

  const findCol = (candidates) => header.findIndex((h) => candidates.includes(h));
  const idxName = findCol(["name", "title", "service", "app", "名称", "标题", "平台", "网站名称", "系统名称"]);
  const idxUrl = findCol(["url", "login_uri", "website", "uri", "host", "网址", "链接", "地址", "域名"]);
  const idxUser = findCol(["username", "login_username", "user", "account", "email", "账号", "用户名", "账户", "邮箱", "登录名"]);
  const idxPwd = findCol(["password", "login_password", "pass", "secret", "密码", "口令", "登录密码"]);
  const idxTotp = findCol(["totp", "login_totp", "otp", "2fa", "两步验证", "动态码"]);
  const idxNote = findCol(["note", "notes", "comment", "remark", "备注", "说明"]);
  const idxScope = findCol(["scope", "pwdsvscope", "platform", "端口", "适用端", "平台类型"]);
  const idxFolder = findCol(["folder", "group", "category", "文件夹", "分组", "分类"]);

  // 必须至少明确认出密码列，以及（用户名列 或 网址列 或 名称列）才走确定性免 AI 通道
  if (idxPwd < 0 || (idxUser < 0 && idxUrl < 0 && idxName < 0)) {
    return null;
  }

  const out = [];
  for (const r of rows.slice(1)) {
    const password = (r[idxPwd] || "").trim();
    const username = idxUser >= 0 ? (r[idxUser] || "").trim() : "";
    const uri = idxUrl >= 0 ? (r[idxUrl] || "").trim() : "";
    const name = (idxName >= 0 ? (r[idxName] || "").trim() : "") || uri || username;
    if (!password && !username) continue;

    out.push({
      name: name || "导入账号",
      username,
      password,
      totp: idxTotp >= 0 ? (r[idxTotp] || "").trim() : "",
      uris: uri ? uri.split(/[;\s]+/).filter(Boolean) : [],
      pwdsvScope: idxScope >= 0 ? (r[idxScope] || "").trim() : "",
      folderName: idxFolder >= 0 ? (r[idxFolder] || "").trim() : "",
      notes: idxNote >= 0 ? (r[idxNote] || "").trim() : (sourceName ? `导入自 ${sourceName}` : ""),
      confidence: 1.0,
    });
  }
  return out.length ? out : null;
}

/* ---------------------------------------------------------- Excel .xlsx 解析 */

function colLettersToIndex(cellRef) {
  const m = String(cellRef || "").match(/^[A-Z]+/i);
  if (!m) return 0;
  let idx = 0;
  for (const ch of m[0].toUpperCase()) {
    idx = idx * 26 + (ch.charCodeAt(0) - 64);
  }
  return Math.max(0, idx - 1);
}

export async function extractXlsxContent(bytes) {
  const entries = await unzipEntries(bytes);

  // 1. 解析共享字符串表 xl/sharedStrings.xml
  const sharedStrings = [];
  const sstXml = decodeUtf8(entries.get("xl/sharedStrings.xml"));
  if (sstXml) {
    const siMatches = sstXml.match(/<si\b[^>]*>[\s\S]*?<\/si>/gi) || [];
    for (const si of siMatches) {
      const texts = [];
      const tMatches = si.match(/<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/gi) || [];
      for (const t of tMatches) {
        texts.push(decodeEntities(t.replace(/^<t[^>]*>|<\/t>$/gi, "")));
      }
      sharedStrings.push(texts.join(""));
    }
  }

  // 2. 解析工作簿 Sheet 名称
  const sheetNames = [];
  const wbXml = decodeUtf8(entries.get("xl/workbook.xml"));
  if (wbXml) {
    const sMatches = wbXml.match(/<sheet\b[^>]*>/gi) || [];
    for (const tag of sMatches) {
      const nm = tag.match(/\bname="([^"]*)"/i);
      if (nm) sheetNames.push(decodeEntities(nm[1]));
    }
  }

  // 3. 逐个解析 xl/worksheets/sheet*.xml
  const sheetPaths = [...entries.keys()]
    .filter((k) => /^xl\/worksheets\/sheet\d+\.xml$/i.test(k))
    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));

  const allRows = [];
  const textBlocks = [];

  sheetPaths.forEach((path, idx) => {
    const xml = decodeUtf8(entries.get(path));
    const sheetTitle = sheetNames[idx] || `Sheet${idx + 1}`;
    const sheetRows = [];

    const rowMatches = xml.match(/<row\b[^>]*>[\s\S]*?<\/row>/gi) || [];
    for (const rowXml of rowMatches) {
      const rowArr = [];
      const cellMatches = rowXml.match(/<c\b[^>]*>(?:[\s\S]*?<\/c>)?/gi) || [];
      let nextCol = 0;
      for (const cXml of cellMatches) {
        const refMatch = cXml.match(/\br="([A-Z]+\d+)"/i);
        const colIdx = refMatch ? colLettersToIndex(refMatch[1]) : nextCol;
        nextCol = colIdx + 1;

        const typeMatch = cXml.match(/\bt="([^"]*)"/i);
        const cType = typeMatch ? typeMatch[1] : "";
        let val = "";

        if (cType === "inlineStr") {
          const tMatch = cXml.match(/<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/i);
          val = tMatch ? decodeEntities(tMatch[1]) : "";
        } else {
          const vMatch = cXml.match(/<v>([\s\S]*?)<\/v>/i);
          const rawV = vMatch ? decodeEntities(vMatch[1]) : "";
          if (cType === "s") {
            val = sharedStrings[Number(rawV)] ?? rawV;
          } else {
            val = rawV;
          }
        }
        rowArr[colIdx] = String(val ?? "").trim();
      }
      const normalized = Array.from({ length: rowArr.length }, (_, i) => rowArr[i] || "");
      if (normalized.some((x) => x !== "")) {
        sheetRows.push(normalized);
      }
    }

    if (sheetRows.length) {
      if (sheetPaths.length === 1) allRows.push(...sheetRows);
      const lines = sheetRows.map((r) => r.join(" | ")).join("\n");
      textBlocks.push(`### 工作表：${sheetTitle}\n${lines}`);
    }
  });

  return {
    rows: allRows,
    text: textBlocks.join("\n\n"),
  };
}

/* ----------------------------------------------------------- Word .docx 解析 */

export async function extractDocxText(bytes) {
  const entries = await unzipEntries(bytes);
  const docXml = decodeUtf8(entries.get("word/document.xml"));
  if (!docXml) throw new Error("Word 文档中未找到正文内容 (word/document.xml)");

  const blocks = [];
  // 按表格或段落顺序抽取，保留表格行列结构
  const tokenRegex = /<w:tbl\b[\s\S]*?<\/w:tbl>|<w:p\b[\s\S]*?<\/w:p>/gi;
  let match;
  while ((match = tokenRegex.exec(docXml)) !== null) {
    const chunk = match[0];
    if (/^<w:tbl\b/i.test(chunk)) {
      const trs = chunk.match(/<w:tr\b[\s\S]*?<\/w:tr>/gi) || [];
      for (const tr of trs) {
        const tcs = tr.match(/<w:tc\b[\s\S]*?<\/w:tc>/gi) || [];
        const cells = tcs.map((tc) => {
          const ts = tc.match(/<w:t(?:\s[^>]*)?>([\s\S]*?)<\/w:t>/gi) || [];
          return ts.map((t) => decodeEntities(t.replace(/^<w:t[^>]*>|<\/w:t>$/gi, ""))).join("").trim();
        });
        if (cells.some(Boolean)) blocks.push(cells.join(" | "));
      }
    } else {
      const ts = chunk.match(/<w:t(?:\s[^>]*)?>([\s\S]*?)<\/w:t>/gi) || [];
      const line = ts.map((t) => decodeEntities(t.replace(/^<w:t[^>]*>|<\/w:t>$/gi, ""))).join("").trim();
      if (line) blocks.push(line);
    }
  }
  return blocks.join("\n");
}

/* ------------------------------------------------------------ PDF 文本层提取 */

async function tryInflateZlib(slice) {
  for (const fmt of ["deflate", "deflate-raw"]) {
    try {
      const ds = new DecompressionStream(fmt);
      const w = ds.writable.getWriter();
      w.write(slice);
      w.close();
      const parts = [];
      const r = ds.readable.getReader();
      while (true) {
        const { value, done } = await r.read();
        if (done) break;
        if (value) parts.push(value);
      }
      const len = parts.reduce((n, b) => n + b.byteLength, 0);
      const out = new Uint8Array(len);
      let off = 0;
      for (const p of parts) {
        out.set(p, off);
        off += p.byteLength;
      }
      return out;
    } catch {
      /* 尝试下一种格式 */
    }
  }
  return null;
}

function decodePdfLiteral(str) {
  return str
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t")
    .replace(/\\\(/g, "(")
    .replace(/\\\)/g, ")")
    .replace(/\\\\/g, "\\");
}

function decodePdfHex(hex) {
  const clean = hex.replace(/\s+/g, "");
  const bytes = new Uint8Array(Math.floor(clean.length / 2));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16) || 0;
  }
  // UTF-16BE BOM
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    let out = "";
    for (let i = 2; i + 1 < bytes.length; i += 2) {
      out += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
    }
    return out;
  }
  return TD_UTF8.decode(bytes);
}

function extractTextOperators(contentStr) {
  const pieces = [];
  const btBlocks = contentStr.match(/BT[\s\S]*?ET/g) || [contentStr];
  for (const blk of btBlocks) {
    const tokenRe = /\((?:\\.|[^\\)])*\)|<([0-9A-Fa-f\s]{2,})>/g;
    let m;
    const lineParts = [];
    while ((m = tokenRe.exec(blk)) !== null) {
      if (m[0].startsWith("(")) {
        lineParts.push(decodePdfLiteral(m[0].slice(1, -1)));
      } else if (m[1]) {
        lineParts.push(decodePdfHex(m[1]));
      }
    }
    const joined = lineParts.join("").trim();
    if (joined) pieces.push(joined);
  }
  return pieces.join("\n");
}

export async function extractPdfContent(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const latin = new TextDecoder("latin1").decode(u8);
  const texts = [];

  const streamRe = /stream\r?\n([\s\S]*?)\r?\nendstream/g;
  let m;
  while ((m = streamRe.exec(latin)) !== null) {
    const rawStr = m[1];
    const startIdx = m.index + m[0].indexOf(rawStr);
    const slice = u8.subarray(startIdx, startIdx + rawStr.length);
    const inflated = await tryInflateZlib(slice);
    const decoded = inflated ? new TextDecoder("latin1").decode(inflated) : rawStr;
    if (decoded.includes("BT") || decoded.includes("Tj") || decoded.includes("TJ")) {
      const t = extractTextOperators(decoded);
      if (t) texts.push(t);
    }
  }

  const combined = texts.join("\n").replace(/\u0000/g, "").trim();
  return {
    text: combined,
    isScannedOrVisual: combined.length < 16,
    base64: bytesToBase64(u8),
  };
}

/* ------------------------------------------------------------ 统一文件分派入口 */

/**
 * 识别任意输入文件并提取为可供快筛或 AI 解析的中间载荷
 * @param {{ name: string, mimeType?: string, bytes: Uint8Array|ArrayBuffer }} file
 */
export async function extractFilePayload(file) {
  const name = String(file?.name || "未命名文件");
  const lower = name.toLowerCase();
  const mime = String(file?.mimeType || "").toLowerCase();
  const bytes = file.bytes instanceof Uint8Array ? file.bytes : new Uint8Array(file.bytes);

  // 1. 图片文件（截图、手机拍照）
  if (mime.startsWith("image/") || /\.(png|jpe?g|webp|gif|bmp)$/i.test(lower)) {
    const detectedMime = mime.startsWith("image/")
      ? mime
      : lower.endsWith(".png")
        ? "image/png"
        : lower.endsWith(".webp")
          ? "image/webp"
          : "image/jpeg";
    return {
      kind: "image",
      fileName: name,
      mimeType: detectedMime,
      base64: bytesToBase64(bytes),
      text: "",
      fastItems: null,
    };
  }

  // 2. Excel (.xlsx)
  if (lower.endsWith(".xlsx") || mime.includes("spreadsheetml")) {
    const { rows, text } = await extractXlsxContent(bytes);
    const fastItems = tryFastParseTabular(rows, name);
    return {
      kind: "spreadsheet",
      fileName: name,
      text,
      fastItems,
    };
  }

  // 3. Word (.docx)
  if (lower.endsWith(".docx") || mime.includes("wordprocessingml")) {
    const text = await extractDocxText(bytes);
    return {
      kind: "document",
      fileName: name,
      text,
      fastItems: null,
    };
  }

  // 4. PDF (.pdf)
  if (lower.endsWith(".pdf") || mime === "application/pdf") {
    const pdf = await extractPdfContent(bytes);
    return {
      kind: pdf.isScannedOrVisual ? "pdf-visual" : "document",
      fileName: name,
      mimeType: "application/pdf",
      base64: pdf.base64,
      text: pdf.text,
      fastItems: null,
    };
  }

  // 5. CSV / TSV / JSON / TXT / Markdown 等文本类格式
  const rawText = TD_UTF8.decode(bytes);
  if (lower.endsWith(".csv") || lower.endsWith(".tsv") || mime === "text/csv") {
    const delim = lower.endsWith(".tsv") ? "\t" : ",";
    const rows = parseDelimitedRows(rawText, delim);
    const fastItems = tryFastParseTabular(rows, name);
    return {
      kind: "tabular",
      fileName: name,
      text: rawText,
      fastItems,
    };
  }

  if (lower.endsWith(".json") || mime === "application/json") {
    try {
      const parsed = JSON.parse(rawText);
      // Bitwarden 官方 JSON 导出快筛
      if (Array.isArray(parsed?.items)) {
        const bwItems = parsed.items
          .filter((it) => it?.login && (it.login.password || it.login.username))
          .map((it) => ({
            name: it.name || "导入账号",
            username: it.login.username || "",
            password: it.login.password || "",
            totp: it.login.totp || "",
            uris: (it.login.uris || []).map((u) => u?.uri).filter(Boolean),
            pwdsvScope: it.pwdsvScope || "",
            notes: it.notes || "",
            confidence: 1.0,
          }));
        if (bwItems.length) {
          return { kind: "json", fileName: name, text: rawText, fastItems: bwItems };
        }
      }
    } catch {
      /* 非标准 JSON 交由 AI 解析 */
    }
  }

  return {
    kind: "text",
    fileName: name,
    text: rawText,
    fastItems: null,
  };
}
