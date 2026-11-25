/**
 * 把服务端返回的加密数据变成能用的明文，以及把明文重新组装成新建 / 更新 / 批量导入请求体。
 *
 * 同时维护四态密码作用域（pwdsvScope: "universal" | "web" | "desktop" | "mobile"）：
 * - 顶层字段 `pwdsvScope` 与 `pwdsvOriginDevice` 供服务端直接区分、检索与统计
 * - 加密自定义字段 `_pwdsv_scope` 随端到端密文同步备份
 */

import {
  stretchKey,
  decryptText,
  decryptBytes,
  encryptText,
  keyFromBytes,
  rsaDecrypt,
} from "./crypto.js";
import { normalizeScope, resolveItemScope } from "./matcher.js";

const CIPHER_TYPE_LOGIN = 1;
const MAX_PASSWORD_HISTORY = 5;

async function tryDecrypt(key, encString) {
  if (!encString || typeof encString !== "string") return "";
  try {
    return await decryptText(key, encString);
  } catch {
    return "";
  }
}

export async function unlockUserKey(profile, masterKey) {
  const stretched = await stretchKey(masterKey);
  const encKey = profile?.key;
  if (encKey) {
    const raw = await decryptBytes(stretched, encKey);
    return { stretched, userKey: keyFromBytes(raw) };
  }
  return { stretched, userKey: stretched };
}

async function loadPrivateKey(profile, userKey) {
  const enc = profile?.privateKey;
  if (!enc) return null;
  try {
    return await decryptBytes(userKey, enc);
  } catch {
    return null;
  }
}

export async function loadOrgKeys(profile, userKey) {
  const map = new Map();
  const privateKey = await loadPrivateKey(profile, userKey);
  if (!privateKey) return map;

  for (const org of profile?.organizations || []) {
    if (!org?.id || !org?.key) continue;
    try {
      const raw = await rsaDecrypt(privateKey, org.key);
      map.set(org.id, keyFromBytes(raw));
    } catch {
      /* 解不开只影响单个组织条目 */
    }
  }
  return map;
}

async function keyForCipher(cipher, userKey, orgKeys) {
  if (cipher?.key) {
    try {
      const raw = await decryptBytes(userKey, cipher.key);
      return keyFromBytes(raw);
    } catch {
      /* 落到下面 */
    }
  }
  if (cipher?.organizationId && orgKeys?.has(cipher.organizationId)) {
    return orgKeys.get(cipher.organizationId);
  }
  return userKey;
}

const TYPE_NAMES = { 1: "登录", 2: "笔记", 3: "卡片", 4: "身份", 5: "SSH 密钥" };

/** 解一条 cipher */
export async function decryptCipher(cipher, userKey, orgKeys) {
  const base = {
    id: cipher.id,
    type: cipher.type,
    typeName: TYPE_NAMES[cipher.type] || "条目",
    favorite: Boolean(cipher.favorite),
    reprompt: Number(cipher.reprompt || 0),
    folderId: cipher.folderId || null,
    organizationId: cipher.organizationId || null,
    collectionIds: Array.isArray(cipher.collectionIds) ? cipher.collectionIds : [],
    revisionDate: cipher.revisionDate || null,
    deletedDate: cipher.deletedDate || null,
    cipherKeyEnc: cipher.key || null,
    pwdsvScope: normalizeScope(cipher.pwdsvScope) || "universal",
    pwdsvOriginDevice: cipher.pwdsvOriginDevice || null,
    status: "ok",
    name: "",
    username: "",
    password: "",
    passwordRevisionDate: null,
    totp: "",
    notes: "",
    uris: [],
    fields: [],
    passwordHistory: [],
  };

  let key;
  try {
    key = await keyForCipher(cipher, userKey, orgKeys);
  } catch (e) {
    return { ...base, status: "error", error: String(e?.message || e), name: "（解不开）" };
  }

  try {
    const name = await tryDecrypt(key, cipher.name);
    const notes = await tryDecrypt(key, cipher.notes);

    let username = "";
    let password = "";
    let totp = "";
    let passwordRevisionDate = null;
    const uris = [];
    const login = cipher.login;
    if (login) {
      username = await tryDecrypt(key, login.username);
      password = await tryDecrypt(key, login.password);
      totp = await tryDecrypt(key, login.totp);
      passwordRevisionDate = login.passwordRevisionDate || null;
      if (Array.isArray(login.uris)) {
        for (const u of login.uris) {
          const uri = await tryDecrypt(key, u?.uri);
          if (uri) uris.push({ uri, match: u?.match ?? null });
        }
      }
    }

    const fields = [];
    if (Array.isArray(cipher.fields)) {
      for (const f of cipher.fields) {
        fields.push({
          name: await tryDecrypt(key, f?.name),
          value: await tryDecrypt(key, f?.value),
          type: Number(f?.type ?? 0),
          linkedId: f?.linkedId ?? null,
        });
      }
    }

    const passwordHistory = [];
    if (Array.isArray(cipher.passwordHistory)) {
      for (const h of cipher.passwordHistory) {
        const oldPwd = await tryDecrypt(key, h?.password);
        if (oldPwd) {
          passwordHistory.push({
            lastUsedDate: h?.lastUsedDate || new Date().toISOString(),
            password: oldPwd,
          });
        }
      }
    }

    const item = {
      ...base,
      name,
      notes,
      username,
      password,
      passwordRevisionDate,
      totp,
      uris,
      fields,
      passwordHistory,
    };
    item.pwdsvScope = resolveItemScope(item);
    return item;
  } catch (e) {
    return { ...base, status: "error", error: String(e?.message || e) };
  }
}

export async function decryptSync(sync, userKey) {
  const profile = sync?.profile || {};
  const orgKeys = await loadOrgKeys(profile, userKey);

  const folders = [];
  for (const f of sync?.folders || []) {
    folders.push({
      id: f.id,
      name: await tryDecrypt(userKey, f.name),
      revisionDate: f.revisionDate || null,
    });
  }
  const folderNames = new Map(folders.map((f) => [f.id, f.name]));

  const items = [];
  for (const c of sync?.ciphers || []) {
    if (c?.deletedDate) continue;
    const item = await decryptCipher(c, userKey, orgKeys);
    item.folderName = folderNames.get(item.folderId) || "";
    items.push(item);
  }

  return { items, folders, profile, domains: sync?.domains || null };
}

/**
 * 组装「新建 / 更新 / 导入登录条目」的加密请求体。
 */
export async function buildLoginCipherPayload({
  name,
  username = "",
  password = "",
  totp = "",
  uri = "",
  uris = null,
  notes = "",
  folderId = null,
  favorite = false,
  fields = null,
  pwdsvScope = null,
  pwdsvOriginDevice = null,
}, { userKey, userId, keyId = null, existingItem = null }) {
  let encKeyObj = userKey;
  if (existingItem?.cipherKeyEnc) {
    try {
      const raw = await decryptBytes(userKey, existingItem.cipherKeyEnc);
      encKeyObj = keyFromBytes(raw);
    } catch {
      encKeyObj = userKey;
    }
  }

  const enc = async (v) =>
    v === "" || v === null || v === undefined ? null : encryptText(encKeyObj, String(v));

  let rawUris = [];
  if (Array.isArray(uris)) {
    rawUris = uris
      .map((u) => (typeof u === "string" ? { uri: u.trim(), match: null } : { uri: String(u?.uri || "").trim(), match: u?.match ?? null }))
      .filter((u) => u.uri);
  } else if (uri && String(uri).trim()) {
    rawUris = [{ uri: String(uri).trim(), match: null }];
  } else if (existingItem?.uris?.length) {
    rawUris = existingItem.uris;
  }

  const encUris = [];
  for (const u of rawUris) {
    encUris.push({ match: u.match ?? null, uri: await enc(u.uri) });
  }

  const resolvedScope =
    normalizeScope(pwdsvScope) ||
    (existingItem ? resolveItemScope(existingItem) : resolveItemScope({ uris: rawUris }));

  const baseFields = (Array.isArray(fields) ? fields : existingItem?.fields || []).filter(
    (f) => f?.name !== "_pwdsv_scope",
  );
  baseFields.push({ name: "_pwdsv_scope", value: resolvedScope, type: 0 });

  const encFields = [];
  for (const f of baseFields) {
    if (!f?.name && !f?.value) continue;
    encFields.push({
      name: await enc(f.name || ""),
      value: await enc(f.value || ""),
      type: Number(f.type ?? 0),
      linkedId: f.linkedId ?? null,
    });
  }

  const nowIso = new Date().toISOString();
  let passwordRevisionDate = existingItem?.passwordRevisionDate || null;
  let historyPlain = Array.isArray(existingItem?.passwordHistory) ? [...existingItem.passwordHistory] : [];
  if (existingItem && existingItem.password && existingItem.password !== password) {
    passwordRevisionDate = nowIso;
    historyPlain = [
      { lastUsedDate: nowIso, password: existingItem.password },
      ...historyPlain,
    ].slice(0, MAX_PASSWORD_HISTORY);
  }

  const encHistory = [];
  for (const h of historyPlain) {
    if (!h?.password) continue;
    encHistory.push({
      lastUsedDate: h.lastUsedDate || nowIso,
      password: await enc(h.password),
    });
  }

  const payload = {
    type: CIPHER_TYPE_LOGIN,
    name: await encryptText(encKeyObj, name || rawUris[0]?.uri || "未命名"),
    notes: await enc(notes),
    favorite: Boolean(favorite),
    reprompt: Number(existingItem?.reprompt || 0),
    folderId: folderId || null,
    organizationId: existingItem?.organizationId || null,
    encryptedFor: userId,
    encryptedByKeyId: keyId || null,
    pwdsvScope: resolvedScope,
    pwdsvOriginDevice: pwdsvOriginDevice || existingItem?.pwdsvOriginDevice || null,
    login: {
      username: await enc(username),
      password: await enc(password),
      totp: await enc(totp),
      passwordRevisionDate,
      uris: encUris,
    },
    fields: encFields,
    passwordHistory: encHistory,
  };

  if (existingItem?.cipherKeyEnc) {
    payload.key = existingItem.cipherKeyEnc;
  }
  return payload;
}

export async function buildNewLoginCipher(data, ctx) {
  return buildLoginCipherPayload(data, ctx);
}
