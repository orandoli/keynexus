"""Argon2id 参考实现（慢，但写法直白，用来给 JS 实现当对照）"""
import hashlib, struct, sys

M64 = (1 << 64) - 1

def blake2b(data, outlen):
    return hashlib.blake2b(data, digest_size=outlen).digest()

def H_prime(outlen, data):
    return struct.pack("<I", outlen) and _hprime(outlen, data)

def _hprime(outlen, data):
    if outlen <= 64:
        return blake2b(struct.pack("<I", outlen) + data, outlen)
    r = (outlen + 31) // 32 - 2
    out = bytearray()
    v = blake2b(struct.pack("<I", outlen) + data, 64)
    out += v[:32]
    for _ in range(1, r):
        v = blake2b(v, 64)
        out += v[:32]
    v = blake2b(v, outlen - 32 * r)
    out += v
    return bytes(out)

def rotr(x, n):
    return ((x >> n) | (x << (64 - n))) & M64

def blamka(x, y):
    xy = ((x & 0xFFFFFFFF) * (y & 0xFFFFFFFF))
    return (x + y + 2 * xy) & M64

def G(v, a, b, c, d):
    v[a] = blamka(v[a], v[b]); v[d] = rotr(v[d] ^ v[a], 32)
    v[c] = blamka(v[c], v[d]); v[b] = rotr(v[b] ^ v[c], 24)
    v[a] = blamka(v[a], v[b]); v[d] = rotr(v[d] ^ v[a], 16)
    v[c] = blamka(v[c], v[d]); v[b] = rotr(v[b] ^ v[c], 63)

def permute(v, idx):
    # idx: 16 个字的全局下标
    w = [v[i] for i in idx]
    G(w, 0, 4, 8, 12); G(w, 1, 5, 9, 13); G(w, 2, 6, 10, 14); G(w, 3, 7, 11, 15)
    G(w, 0, 5, 10, 15); G(w, 1, 6, 11, 12); G(w, 2, 7, 8, 13); G(w, 3, 4, 9, 14)
    for k, i in enumerate(idx):
        v[i] = w[k]

def compress(prev, ref, old=None):
    R = [prev[i] ^ ref[i] for i in range(128)]
    Z = list(R)
    for i in range(8):
        permute(Z, [16 * i + j for j in range(16)])
    for i in range(8):
        permute(Z, [2 * i + 16 * k + m for k in range(8) for m in (0, 1)])
    out = [(Z[i] ^ R[i]) for i in range(128)]
    if old is not None:
        out = [out[i] ^ old[i] for i in range(128)]
    return out

def argon2id(password, salt, t=3, m=32, p=1, hashlen=32, secret=b"", ad=b""):
    m_prime = (m * 1024 // (4 * p)) * 4 * p if m * 1024 >= 8 * p else 8 * p
    lane_len = m_prime // p
    seg_len = lane_len // 4
    h0 = blake2b(
        struct.pack("<IIII", p, hashlen, m_prime, t) + struct.pack("<II", 0x13, 2)
        + struct.pack("<I", len(password)) + password
        + struct.pack("<I", len(salt)) + salt
        + struct.pack("<I", len(secret)) + secret
        + struct.pack("<I", len(ad)) + ad, 64)

    mem = [[0] * 128 for _ in range(m_prime)]
    for lane in range(p):
        for j in (0, 1):
            blk = _hprime(1024, h0 + struct.pack("<II", j, lane))
            mem[lane * lane_len + j] = list(struct.unpack("<128Q", blk))

    addr = [0] * 128
    inp = [0] * 128
    zero = [0] * 128

    def index_alpha(pas, sl, index, same_lane, j1):
        if pas == 0:
            if sl == 0:
                area = index - 1
            elif same_lane:
                area = sl * seg_len + index - 1
            else:
                area = sl * seg_len + (-1 if index == 0 else 0)
        else:
            if same_lane:
                area = lane_len - seg_len + index - 1
            else:
                area = lane_len - seg_len + (-1 if index == 0 else 0)
        rel = (j1 * j1) >> 32
        rel = area - 1 - ((area * rel) >> 32)
        start = 0 if pas == 0 else (0 if sl == 3 else (sl + 1) * seg_len)
        return (start + rel) % lane_len

    for pas in range(t):
        for sl in range(4):
            for lane in range(p):
                di = pas == 0 and sl < 2
                counter = 0
                if di:
                    inp = [0] * 128
                    inp[0] = pas; inp[1] = lane; inp[2] = sl
                    inp[3] = m_prime; inp[4] = t; inp[5] = 2
                start_idx = 2 if (pas == 0 and sl == 0) else 0
                if di and start_idx == 2:
                    counter += 1
                    inp[6] = counter
                    addr = compress(zero, inp)
                    addr = compress(zero, addr)
                for index in range(start_idx, seg_len):
                    cur = sl * seg_len + index
                    prev_i = lane_len - 1 if cur == 0 else cur - 1
                    prev = mem[lane * lane_len + prev_i]
                    if di:
                        if index % 128 == 0:
                            counter += 1
                            inp[6] = counter
                            addr = compress(zero, inp)
                            addr = compress(zero, addr)
                        pseudo = addr[index % 128]
                    else:
                        pseudo = prev[0]
                    j1 = pseudo & 0xFFFFFFFF
                    j2 = pseudo >> 32
                    ref_lane = lane if (pas == 0 and sl == 0) else (j2 % p)
                    ref_i = index_alpha(pas, sl, index, ref_lane == lane, j1)
                    ref = mem[ref_lane * lane_len + ref_i]
                    cur_block = mem[lane * lane_len + cur]
                    mem[lane * lane_len + cur] = compress(prev, ref, cur_block if pas > 0 else None)
    final = [0] * 128
    for lane in range(p):
        blk = mem[lane * lane_len + lane_len - 1]
        final = [final[i] ^ blk[i] for i in range(128)]
    return _hprime(hashlen, struct.pack("<128Q", *final))

if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "rfc":
        pwd = b"\x01" * 32; salt = b"\x02" * 16; sec = b"\x03" * 8; ad = b"\x04" * 12
        out = argon2id(pwd, salt, t=3, m=32, p=4, hashlen=32, secret=sec, ad=ad)
        print(out.hex())
    elif mode == "sdk":
        pwd = b"67t9b5g67$%Dh89n"
        salt = hashlib.sha256(b"test_key").digest()
        out = argon2id(pwd, salt, t=4, m=32, p=2, hashlen=32)
        print(out.hex())
    elif mode == "small":
        t, m, p = int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
        pwd = b"password"; salt = hashlib.sha256(b"user@example.com").digest()
        print(argon2id(pwd, salt, t=t, m=m, p=p, hashlen=32).hex())
