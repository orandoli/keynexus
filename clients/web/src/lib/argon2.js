/**
 * PWDSV 浏览器插件 —— Argon2id（纯 JS，无依赖）
 *
 * WebCrypto 里没有 Argon2，而 Bitwarden/PWDSV 的账号可以把 KDF 设成 Argon2id，
 * 所以这里照 RFC 9106 自己实现一份，参数和官方 SDK 完全一致：
 *
 *   salt   = SHA-256(小写去空格的邮箱)   ← 由调用方（crypto.js）算好传进来
 *   memory = 多少 MiB（这里换算成 KiB 参与计算）
 *   type   = Argon2id(2)，version = 0x13，输出长度默认 32B
 *
 * 验证用的是官方 SDK 的测试向量，见 test/argon2.test.mjs。
 * 所有 64 位运算都用 lo/hi 两段 32 位整数模拟，避免 BigInt 拖慢速度。
 */

const ARGON2_TYPE_ID = 2;
const ARGON2_VERSION = 0x13;
const SYNC_POINTS = 4;
const ADDRESSES_IN_BLOCK = 128;
const BLOCK_WORDS = 128;          // 1024 字节 = 128 个 64 位字
const BLOCK_HALVES = BLOCK_WORDS * 2;

/* --------------------------------------------------------------- Blake2b 基础 */

const IV_LO = new Uint32Array([
  0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1, 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179,
]);
const IV_HI = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

// Blake2b 压缩函数用到的临时数组（避免每次 hash 都分配）
const b2vLo = new Uint32Array(16);
const b2vHi = new Uint32Array(16);

function b2Add(alo, ahi, blo, bhi) {
  const lo = alo + blo;
  const carry = lo > 0xffffffff ? 1 : 0;
  b2tLo = lo >>> 0;
  b2tHi = (ahi + bhi + carry) >>> 0;
}
let b2tLo = 0, b2tHi = 0;

function b2Xor(alo, ahi, blo, bhi) {
  b2tLo = (alo ^ blo) >>> 0;
  b2tHi = (ahi ^ bhi) >>> 0;
}

function b2Rotr(lo, hi, n) {
  if (n === 32) {
    b2tLo = hi >>> 0;
    b2tHi = lo >>> 0;
  } else if (n === 24) {
    b2tLo = ((lo >>> 24) | (hi << 8)) >>> 0;
    b2tHi = ((hi >>> 24) | (lo << 8)) >>> 0;
  } else if (n === 16) {
    b2tLo = ((lo >>> 16) | (hi << 16)) >>> 0;
    b2tHi = ((hi >>> 16) | (lo << 16)) >>> 0;
  } else if (n === 63) {
    b2tLo = ((lo << 1) | (hi >>> 31)) >>> 0;
    b2tHi = ((hi << 1) | (lo >>> 31)) >>> 0;
  } else {
    throw new Error("Blake2b 不支持的旋转量：" + n);
  }
}

function b2G(vLo, vHi, a, b, c, d, xLo, xHi, yLo, yHi) {
  // a = a + b + x
  b2Add(vLo[a], vHi[a], vLo[b], vHi[b]);
  b2Add(b2tLo, b2tHi, xLo, xHi);
  vLo[a] = b2tLo;
  vHi[a] = b2tHi;
  // d = (d ^ a) >>> 32
  b2Xor(vLo[d], vHi[d], vLo[a], vHi[a]);
  b2Rotr(b2tLo, b2tHi, 32);
  vLo[d] = b2tLo;
  vHi[d] = b2tHi;
  // c = c + d
  b2Add(vLo[c], vHi[c], vLo[d], vHi[d]);
  vLo[c] = b2tLo;
  vHi[c] = b2tHi;
  // b = (b ^ c) >>> 24
  b2Xor(vLo[b], vHi[b], vLo[c], vHi[c]);
  b2Rotr(b2tLo, b2tHi, 24);
  vLo[b] = b2tLo;
  vHi[b] = b2tHi;
  // a = a + b + y
  b2Add(vLo[a], vHi[a], vLo[b], vHi[b]);
  b2Add(b2tLo, b2tHi, yLo, yHi);
  vLo[a] = b2tLo;
  vHi[a] = b2tHi;
  // d = (d ^ a) >>> 16
  b2Xor(vLo[d], vHi[d], vLo[a], vHi[a]);
  b2Rotr(b2tLo, b2tHi, 16);
  vLo[d] = b2tLo;
  vHi[d] = b2tHi;
  // c = c + d
  b2Add(vLo[c], vHi[c], vLo[d], vHi[d]);
  vLo[c] = b2tLo;
  vHi[c] = b2tHi;
  // b = (b ^ c) >>> 63
  b2Xor(vLo[b], vHi[b], vLo[c], vHi[c]);
  b2Rotr(b2tLo, b2tHi, 63);
  vLo[b] = b2tLo;
  vHi[b] = b2tHi;
}

/** Blake2b-512 的压缩：把 128 字节 block 混进状态，t 是已处理字节数（64 位用 Number 足够） */
function b2Compress(hLo, hHi, mHalves, tLow, tHigh, last) {
  for (let i = 0; i < 8; i++) {
    b2vLo[i] = hLo[i];
    b2vHi[i] = hHi[i];
    b2vLo[i + 8] = IV_LO[i];
    b2vHi[i + 8] = IV_HI[i];
  }
  // 128 位计数器：v12 异或 t0，v13 异或 t1（消息远小于 2^64 字节，t1 恒为 0）
  b2vLo[12] ^= tLow >>> 0;
  b2vHi[12] ^= tHigh >>> 0;
  b2vLo[13] ^= 0;
  b2vHi[13] ^= 0;
  if (last) {
    b2vLo[14] = ~b2vLo[14] >>> 0;
    b2vHi[14] = ~b2vHi[14] >>> 0;
  }

  for (let r = 0; r < 12; r++) {
    const s = SIGMA[r];
    b2G(b2vLo, b2vHi, 0, 4, 8, 12,
      mHalves[s[0] * 2], mHalves[s[0] * 2 + 1],
      mHalves[s[1] * 2], mHalves[s[1] * 2 + 1]);
    b2G(b2vLo, b2vHi, 1, 5, 9, 13,
      mHalves[s[2] * 2], mHalves[s[2] * 2 + 1],
      mHalves[s[3] * 2], mHalves[s[3] * 2 + 1]);
    b2G(b2vLo, b2vHi, 2, 6, 10, 14,
      mHalves[s[4] * 2], mHalves[s[4] * 2 + 1],
      mHalves[s[5] * 2], mHalves[s[5] * 2 + 1]);
    b2G(b2vLo, b2vHi, 3, 7, 11, 15,
      mHalves[s[6] * 2], mHalves[s[6] * 2 + 1],
      mHalves[s[7] * 2], mHalves[s[7] * 2 + 1]);
    b2G(b2vLo, b2vHi, 0, 5, 10, 15,
      mHalves[s[8] * 2], mHalves[s[8] * 2 + 1],
      mHalves[s[9] * 2], mHalves[s[9] * 2 + 1]);
    b2G(b2vLo, b2vHi, 1, 6, 11, 12,
      mHalves[s[10] * 2], mHalves[s[10] * 2 + 1],
      mHalves[s[11] * 2], mHalves[s[11] * 2 + 1]);
    b2G(b2vLo, b2vHi, 2, 7, 8, 13,
      mHalves[s[12] * 2], mHalves[s[12] * 2 + 1],
      mHalves[s[13] * 2], mHalves[s[13] * 2 + 1]);
    b2G(b2vLo, b2vHi, 3, 4, 9, 14,
      mHalves[s[14] * 2], mHalves[s[14] * 2 + 1],
      mHalves[s[15] * 2], mHalves[s[15] * 2 + 1]);
  }

  for (let i = 0; i < 8; i++) {
    hLo[i] = (hLo[i] ^ b2vLo[i] ^ b2vLo[i + 8]) >>> 0;
    hHi[i] = (hHi[i] ^ b2vHi[i] ^ b2vHi[i + 8]) >>> 0;
  }
}

function le32(n) {
  const b = new Uint8Array(4);
  b[0] = n & 0xff;
  b[1] = (n >>> 8) & 0xff;
  b[2] = (n >>> 16) & 0xff;
  b[3] = (n >>> 24) & 0xff;
  return b;
}

function concat(...arrs) {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** 小端字节 -> 每个 64 位字拆成两段 32 位：[lo, hi] */
function readHalves(bytes) {
  const words = bytes.length >> 3;
  const halves = new Uint32Array(words * 2);
  for (let i = 0; i < words; i++) {
    const o = i * 8;
    halves[i * 2] =
      (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0;
    halves[i * 2 + 1] =
      (bytes[o + 4] | (bytes[o + 5] << 8) | (bytes[o + 6] << 16) | (bytes[o + 7] << 24)) >>> 0;
  }
  return halves;
}

function writeHalves(halves, out) {
  for (let i = 0; i < halves.length / 2; i++) {
    const lo = halves[i * 2];
    const hi = halves[i * 2 + 1];
    out[i * 8] = lo & 0xff;
    out[i * 8 + 1] = (lo >>> 8) & 0xff;
    out[i * 8 + 2] = (lo >>> 16) & 0xff;
    out[i * 8 + 3] = (lo >>> 24) & 0xff;
    out[i * 8 + 4] = hi & 0xff;
    out[i * 8 + 5] = (hi >>> 8) & 0xff;
    out[i * 8 + 6] = (hi >>> 16) & 0xff;
    out[i * 8 + 7] = (hi >>> 24) & 0xff;
  }
  return out;
}

/** 通用 Blake2b（无 key），输出 outLen 字节 */
export function blake2b(input, outLen) {
  const hLo = Uint32Array.from(IV_LO);
  const hHi = Uint32Array.from(IV_HI);
  hLo[0] ^= 0x01010000 ^ outLen;

  const total = input.length;
  let offset = 0;
  // 计数器 t 记的是「到本块结束为止已经吃进去的字节数」
  while (total - offset > 128) {
    b2Compress(hLo, hHi, readHalves(input.subarray(offset, offset + 128)), offset + 128, 0, false);
    offset += 128;
  }
  // 最后一块（补零到 128 字节）
  const lastLen = total - offset;
  const lastBlock = new Uint8Array(128);
  lastBlock.set(input.subarray(offset));
  b2Compress(hLo, hHi, readHalves(lastBlock), total, 0, true);
  void lastLen;

  const out = new Uint8Array(64);
  for (let i = 0; i < 8; i++) {
    out[i * 8] = hLo[i] & 0xff;
    out[i * 8 + 1] = (hLo[i] >>> 8) & 0xff;
    out[i * 8 + 2] = (hLo[i] >>> 16) & 0xff;
    out[i * 8 + 3] = (hLo[i] >>> 24) & 0xff;
    out[i * 8 + 4] = hHi[i] & 0xff;
    out[i * 8 + 5] = (hHi[i] >>> 8) & 0xff;
    out[i * 8 + 6] = (hHi[i] >>> 16) & 0xff;
    out[i * 8 + 7] = (hHi[i] >>> 24) & 0xff;
  }
  return out.subarray(0, outLen);
}

/** Argon2 的变长哈希 H' */
function hPrime(outLen, input) {
  if (outLen <= 64) return blake2b(concat(le32(outLen), input), outLen);
  const r = Math.ceil(outLen / 32) - 2;
  const out = new Uint8Array(outLen);
  let v = blake2b(concat(le32(outLen), input), 64);
  out.set(v.subarray(0, 32), 0);
  for (let i = 1; i < r; i++) {
    v = blake2b(v, 64);
    out.set(v.subarray(0, 32), i * 32);
  }
  const tail = blake2b(v, outLen - 32 * r);
  out.set(tail, 32 * r);
  return out;
}

/* -------------------------------------------------------- Argon2 的块压缩函数 G */

let fbLo = 0, fbHi = 0;

/** fBlaMka(x, y) = x + y + 2 * (x 低 32 位 * y 低 32 位) */
function blamka(alo, ahi, blo, bhi) {
  const a = alo >>> 0;
  const b = blo >>> 0;
  const a0 = a & 0xffff, a1 = a >>> 16;
  const b0 = b & 0xffff, b1 = b >>> 16;
  const p0 = a0 * b0;
  const p1 = a0 * b1 + a1 * b0;
  const p2 = a1 * b1;
  const sum = p0 + p1 * 65536;
  const mulLo = sum % 4294967296;
  const mulHi = (p2 + Math.floor(sum / 4294967296)) % 4294967296;

  const mul2Lo = (mulLo * 2) % 4294967296;
  const mul2Hi = (mulHi * 2 + (mulLo * 2 >= 4294967296 ? 1 : 0)) % 4294967296;

  let lo = alo + blo;
  let carry = lo > 0xffffffff ? 1 : 0;
  lo = lo >>> 0;
  lo = lo + mul2Lo;
  carry += lo > 0xffffffff ? 1 : 0;
  lo = lo >>> 0;
  let hi = (ahi + bhi + carry) >>> 0;
  hi = (hi + mul2Hi) >>> 0;

  fbLo = lo;
  fbHi = hi;
}

function rot64(lo, hi, n) {
  if (n === 32) {
    fbLo = hi >>> 0;
    fbHi = lo >>> 0;
  } else if (n === 24) {
    fbLo = ((lo >>> 24) | (hi << 8)) >>> 0;
    fbHi = ((hi >>> 24) | (lo << 8)) >>> 0;
  } else if (n === 63) {
    // 63 位不是「小于 32 的移位」，单独算，否则会把高低半弄反
    fbLo = ((lo << 1) | (hi >>> 31)) >>> 0;
    fbHi = ((hi << 1) | (lo >>> 31)) >>> 0;
  } else {
    fbLo = ((lo >>> n) | (hi << (32 - n))) >>> 0;
    fbHi = ((hi >>> n) | (lo << (32 - n))) >>> 0;
  }
}

/** 对 16 个 64 位字（用半字偏移给出）做一轮 Blake2b 风格的排列 */
function permute16(arr, o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15) {
  gBlamka(arr, o0, o4, o8, o12);
  gBlamka(arr, o1, o5, o9, o13);
  gBlamka(arr, o2, o6, o10, o14);
  gBlamka(arr, o3, o7, o11, o15);
  gBlamka(arr, o0, o5, o10, o15);
  gBlamka(arr, o1, o6, o11, o12);
  gBlamka(arr, o2, o7, o8, o13);
  gBlamka(arr, o3, o4, o9, o14);
}

function gBlamka(arr, oa, ob, oc, od) {
  let alo = arr[oa], ahi = arr[oa + 1];
  let blo = arr[ob], bhi = arr[ob + 1];
  let clo = arr[oc], chi = arr[oc + 1];
  let dlo = arr[od], dhi = arr[od + 1];

  blamka(alo, ahi, blo, bhi); alo = fbLo; ahi = fbHi;
  dlo = (dlo ^ alo) >>> 0; dhi = (dhi ^ ahi) >>> 0; rot64(dlo, dhi, 32); dlo = fbLo; dhi = fbHi;
  blamka(clo, chi, dlo, dhi); clo = fbLo; chi = fbHi;
  blo = (blo ^ clo) >>> 0; bhi = (bhi ^ chi) >>> 0; rot64(blo, bhi, 24); blo = fbLo; bhi = fbHi;

  blamka(alo, ahi, blo, bhi); alo = fbLo; ahi = fbHi;
  dlo = (dlo ^ alo) >>> 0; dhi = (dhi ^ ahi) >>> 0; rot64(dlo, dhi, 16); dlo = fbLo; dhi = fbHi;
  blamka(clo, chi, dlo, dhi); clo = fbLo; chi = fbHi;
  blo = (blo ^ clo) >>> 0; bhi = (bhi ^ chi) >>> 0; rot64(blo, bhi, 63); blo = fbLo; bhi = fbHi;

  arr[oa] = alo; arr[oa + 1] = ahi;
  arr[ob] = blo; arr[ob + 1] = bhi;
  arr[oc] = clo; arr[oc + 1] = chi;
  arr[od] = dlo; arr[od + 1] = dhi;
}

const scratch = new Uint32Array(BLOCK_HALVES);
const scratchR = new Uint32Array(BLOCK_HALVES);

/**
 * fill_block：next = G(prev, ref)，withXor 为真时再异或上 next 原来的内容。
 * 内存里每个块占 256 个半字。
 */
function fillBlock(prevArr, prevOff, refArr, refOff, nextArr, nextOff, withXor) {
  for (let i = 0; i < BLOCK_HALVES; i++) {
    const v = (prevArr[prevOff + i] ^ refArr[refOff + i]) >>> 0;
    scratch[i] = v;
    scratchR[i] = v;
  }
  // 8 行
  for (let row = 0; row < 8; row++) {
    const b = row * 32;
    permute16(scratch, b, b + 2, b + 4, b + 6, b + 8, b + 10, b + 12, b + 14,
      b + 16, b + 18, b + 20, b + 22, b + 24, b + 26, b + 28, b + 30);
  }
  // 8 列
  for (let col = 0; col < 8; col++) {
    const b = col * 4;
    permute16(scratch, b, b + 2, b + 32, b + 34, b + 64, b + 66, b + 96, b + 98,
      b + 128, b + 130, b + 160, b + 162, b + 192, b + 194, b + 224, b + 226);
  }
  // 结果 = 排列后的 R 再异或回 R（以及 pass>0 时异或旧的块内容）
  if (withXor) {
    for (let i = 0; i < BLOCK_HALVES; i++) {
      nextArr[nextOff + i] = (nextArr[nextOff + i] ^ scratch[i] ^ scratchR[i]) >>> 0;
    }
  } else {
    for (let i = 0; i < BLOCK_HALVES; i++) {
      nextArr[nextOff + i] = (scratch[i] ^ scratchR[i]) >>> 0;
    }
  }
}

/** 乘法取高 32 位：a * b >> 32（a、b 都是 uint32，避免超精度） */
function mul32hi(a, b) {
  const a0 = a & 0xffff, a1 = a >>> 16;
  const b0 = b & 0xffff, b1 = b >>> 16;
  const p0 = a0 * b0;                    // < 2^32
  const p1 = a0 * b1 + a1 * b0;          // < 2^33
  const p2 = a1 * b1;                    // < 2^32
  const low = p1 * 65536 + p0;           // < 2^49，double 能精确表示
  return (p2 + Math.floor(low / 4294967296)) % 4294967296;
}

function indexAlpha(pass, slice, index, sameLane, pseudoLo, instance) {
  const laneLen = instance.laneLen;
  const segLen = instance.segLen;
  let referenceAreaSize;

  if (pass === 0) {
    if (slice === 0) {
      referenceAreaSize = index - 1;
    } else if (sameLane) {
      referenceAreaSize = slice * segLen + index - 1;
    } else {
      referenceAreaSize = slice * segLen + (index === 0 ? -1 : 0);
    }
  } else if (sameLane) {
    referenceAreaSize = laneLen - segLen + index - 1;
  } else {
    referenceAreaSize = laneLen - segLen + (index === 0 ? -1 : 0);
  }

  let rel = mul32hi(pseudoLo, pseudoLo);
  rel = referenceAreaSize - 1 - mul32hi(referenceAreaSize >>> 0, rel >>> 0);

  let startPosition = 0;
  if (pass !== 0) {
    startPosition = slice === SYNC_POINTS - 1 ? 0 : (slice + 1) * segLen;
  }
  // JS 的 % 对负数会返回负值，这里要的是数学取模
  return (startPosition + rel + laneLen * 4) % laneLen;
}

/**
 * Argon2id 主函数。
 * @param {Uint8Array} password
 * @param {Uint8Array} salt 已经是 SHA-256 后的盐
 * @param {{iterations:number, memory:number, parallelism:number, hashLen?:number}} opts
 *        memory 单位是 MiB（和服务端/客户端里的参数一致）
 * @returns {Uint8Array}
 */
export function argon2id(password, salt, opts) {
  const iterations = Math.max(1, opts.iterations | 0);
  const lanes = Math.max(1, opts.parallelism | 0);
  const hashLen = (opts.hashLen | 0) || 32;
  const memoryKiB = Math.max(8 * lanes, opts.memoryKiB ? (opts.memoryKiB | 0) : (opts.memory | 0) * 1024);

  const mPrime = Math.floor(memoryKiB / (SYNC_POINTS * lanes)) * SYNC_POINTS * lanes;
  const laneLen = mPrime / lanes;
  const segLen = laneLen / SYNC_POINTS;

  const instance = { laneLen, segLen };

  const h0 = blake2b(
    concat(
      le32(lanes), le32(hashLen), le32(mPrime), le32(iterations),
      le32(ARGON2_VERSION), le32(ARGON2_TYPE_ID),
      le32(password.length), password,
      le32(salt.length), salt,
      le32(0), le32(0),
    ),
    64,
  );

  const mem = new Uint32Array(mPrime * BLOCK_HALVES);

  // 每个 lane 的前两个块由 H0 派生
  for (let lane = 0; lane < lanes; lane++) {
    for (let j = 0; j < 2; j++) {
      const blockBytes = hPrime(1024, concat(h0, le32(j), le32(lane)));
      const off = (lane * laneLen + j) * BLOCK_HALVES;
      mem.set(readHalves(blockBytes), off);
    }
  }

  const addressBlock = new Uint32Array(BLOCK_HALVES);
  const inputBlock = new Uint32Array(BLOCK_HALVES);
  const zeroBlock = new Uint32Array(BLOCK_HALVES);

  for (let pass = 0; pass < iterations; pass++) {
    for (let slice = 0; slice < SYNC_POINTS; slice++) {
      for (let lane = 0; lane < lanes; lane++) {
        const dataIndependent = pass === 0 && slice < 2;
        let counter = 0;

        if (dataIndependent) {
          inputBlock.fill(0);
          inputBlock[0] = pass;
          inputBlock[2] = lane;
          inputBlock[4] = slice;
          inputBlock[6] = mPrime;
          inputBlock[8] = iterations;
          inputBlock[10] = ARGON2_TYPE_ID;
        }

        const startIndex = pass === 0 && slice === 0 ? 2 : 0;

        // pass0/slice0 从第 2 个块开始，而地址块得先手动生成一次
        const genAddresses = () => {
          counter++;
          inputBlock[12] = counter;
          fillBlock(zeroBlock, 0, inputBlock, 0, addressBlock, 0, false);
          fillBlock(zeroBlock, 0, addressBlock, 0, addressBlock, 0, false);
          if (opts.trace && !opts.addressSample) opts.addressSample = Array.from(addressBlock.slice(0, 8));
        };
        if (dataIndependent && startIndex === 2) genAddresses();

        for (let index = startIndex; index < segLen; index++) {
          const currIndexInLane = slice * segLen + index;
          const laneStart = lane * laneLen;
          const prevIndexInLane = currIndexInLane === 0 ? laneLen - 1 : currIndexInLane - 1;

          const prevOff = (laneStart + prevIndexInLane) * BLOCK_HALVES;
          const nextOff = (laneStart + currIndexInLane) * BLOCK_HALVES;

          let pseudoLo, pseudoHi;
          if (dataIndependent) {
            if (index % ADDRESSES_IN_BLOCK === 0) genAddresses();
            const w = (index % ADDRESSES_IN_BLOCK) * 2;
            pseudoLo = addressBlock[w];
            pseudoHi = addressBlock[w + 1];
          } else {
            pseudoLo = mem[prevOff];
            pseudoHi = mem[prevOff + 1];
          }

          let refLane = pass === 0 && slice === 0 ? lane : pseudoHi % lanes;
          const sameLane = refLane === lane;
          const refIndex = indexAlpha(pass, slice, index, sameLane, pseudoLo, instance);
          if (opts.trace) opts.trace.push({ pass, slice, lane, index, pseudoLo, pseudoHi, refLane, refIndex });
          const refOff = (refLane * laneLen + refIndex) * BLOCK_HALVES;

          fillBlock(mem, prevOff, mem, refOff, mem, nextOff, pass !== 0);
        }
      }
    }
  }

  // 每个 lane 的最后一个块异或起来，再做 H'
  const finalBlock = new Uint32Array(BLOCK_HALVES);
  for (let lane = 0; lane < lanes; lane++) {
    const off = (lane * laneLen + laneLen - 1) * BLOCK_HALVES;
    for (let i = 0; i < BLOCK_HALVES; i++) finalBlock[i] = (finalBlock[i] ^ mem[off + i]) >>> 0;
  }

  const finalBytes = writeHalves(finalBlock, new Uint8Array(1024));
  const tag = hPrime(hashLen, finalBytes);
  if (opts.debug) {
    return { tag, h0, mem, finalBlockBytes: finalBytes };
  }
  return tag;
}

/** 只给测试用的钩子：对两个 1024 字节块做一次 G 压缩 */
export function __testFillBlock(prevBytes, refBytes, withXor, oldBytes) {
  const prev = readHalves(prevBytes);
  const ref = readHalves(refBytes);
  const next = oldBytes ? readHalves(oldBytes) : new Uint32Array(BLOCK_HALVES);
  fillBlock(prev, 0, ref, 0, next, 0, !!withXor);
  return writeHalves(next, new Uint8Array(1024));
}

/** 只给测试用的钩子：对 4 个 64 位字做一次 G */
export function __testG(words) {
  const arr = new Uint32Array(8);
  for (let i = 0; i < 4; i++) {
    arr[i * 2] = words[i][0];
    arr[i * 2 + 1] = words[i][1];
  }
  gBlamka(arr, 0, 2, 4, 6);
  return [[arr[0], arr[1]], [arr[2], arr[3]], [arr[4], arr[5]], [arr[6], arr[7]]];
}

/** 只给测试用的钩子：fBlaMka */
export function __testBlamka(alo, ahi, blo, bhi) {
  blamka(alo, ahi, blo, bhi);
  return [fbLo, fbHi];
}

/** 只给测试用的钩子：只做排列（不做首尾异或） */
export function __testPermute(bytes) {
  const arr = readHalves(bytes);
  for (let row = 0; row < 8; row++) {
    const b = row * 32;
    permute16(arr, b, b + 2, b + 4, b + 6, b + 8, b + 10, b + 12, b + 14,
      b + 16, b + 18, b + 20, b + 22, b + 24, b + 26, b + 28, b + 30);
  }
  for (let col = 0; col < 8; col++) {
    const b = col * 4;
    permute16(arr, b, b + 2, b + 32, b + 34, b + 64, b + 66, b + 96, b + 98,
      b + 128, b + 130, b + 160, b + 162, b + 192, b + 194, b + 224, b + 226);
  }
  return writeHalves(arr, new Uint8Array(1024));
}

/** 只给测试用的钩子：H'(len, input) */
export function __testHPrime(outLen, input) {
  return hPrime(outLen, input);
}
