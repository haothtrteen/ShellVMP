#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
# 本文件是 GNU bash 的衍生作品，许可证由上游强制继承（不可更改）。
# 分发内含魔改 bash 的产物时必须提供对应完整源码。
# -*- coding: utf-8 -*-
"""
v7_embed.py —— 把 V6 骨架加密认证后「内嵌」进改版 bash 二进制尾部（blob v3）。

配套：bash-5.2/lib/sh/zread.c 的 V7 注入 + lib/sh/v7core.c（include crypto_core.h）。
r12 起与路线 A（elfrun/blobgen）**同一套密码学**：

  · KDF     ：scrypt-like ROMix（PBKDF2 → N×128B 顺序填充+随机回访 → PBKDF2）
              N 默认 131072 → 16MB 内存硬度；可用 --scrypt-n 降（安卓低端机）
  · 流密码  ：HMAC-SHA256 密钥流，32B/块 CTR（取代 RC4）
  · 认证    ：Encrypt-then-MAC，tag = HMAC(kmac, ct) 截断 16B + 常数时间比对
  · 模式    ：口令模式（seed=KDF(口令,salt)）/ 离线分发模式（seed 随机 + 白盒编码）

blob v3 布局（追加到 bash ELF 尾部；与 zread.c 的 v7_init 逐字一致）：
  [ct][tag 16][salt 16][N 4 LE][wb_table 256][wb_perm 256][wb_mask 256][flags 4 LE][len 4 LE]
  len = ctlen + 812
  flags bit0：1=口令模式，0=离线（白盒）模式
  两种模式共用布局——口令模式下白盒三表为随机诱饵，无法从布局区分模式。

⚠ 与 C 端的对拍点（改任何一边必须同步另一边）：
  1. kenc = HMAC(seed,"V7ENC")，kmac = HMAC(seed,"V7MAC")（crypto_core.h v7_keys）
  2. 密钥流块 i = HMAC(kenc, be64(i))，每块 32B（v7_keystream）
  3. scrypt_blockmix 是【原地】调用（romix 里 in==out），第 3/4 个 HMAC 读到的是
     已被前一步覆盖的字节 —— _blockmix 必须模拟这个别名效应（v7_embed_alias 实验）。
用法：
  python3 v7_embed.py <V6骨架> <bash二进制> <输出> [--pass '口令'] [--scrypt-n N]
  口令模式：--pass 必填；离线模式：不给 --pass（seed 随机生成，白盒编码内嵌）
运行：
  口令：echo '内层passkey' | V7_SELF=1 V7_PASS='外层口令' ./输出 /dev/null
  离线：V7_SELF=1 ./输出 /dev/null（无口令；内层 passkey 仍走 stdin 若骨架有）
"""
import hashlib
import hmac as hmac_mod
import os
import random
import struct
import sys

WB_SIZE = 256
OVERHEAD = 16 + 16 + 4 + WB_SIZE * 3 + 4 + 4   # tag+salt+N+wb*3+flags+len = 812
FLAG_PASSMODE = 1


def H(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA256 —— 与 crypto_core.h 的 hmac_sha256 一致。"""
    return hmac_mod.new(key, msg, hashlib.sha256).digest()


# ---------------------------------------------------------------- v7_keys
def v7_keys(seed: bytes):
    """seed → (kenc, kmac)。label 与 crypto_core.h 的 V7_LABEL_ENC/MAC 一致。"""
    return H(seed, b"V7ENC"), H(seed, b"V7MAC")


# ---------------------------------------------------------------- keystream
def xor_stream(kenc: bytes, data: bytes) -> bytes:
    """HMAC-SHA256 密钥流 XOR（32B/块，块索引大端 8B）——对齐 v7_crypt。"""
    out = bytearray(len(data))
    for blk in range((len(data) + 31) // 32):
        ks = H(kenc, struct.pack(">Q", blk))
        off = blk * 32
        chunk = data[off:off + 32]
        for i, b in enumerate(chunk):
            out[off + i] = b ^ ks[i]
    return bytes(out)


# ---------------------------------------------------------------- scrypt-like
def _blockmix(in128: bytes) -> bytes:
    """scryptBlockMix 简化版（8 轮 HMAC 链 + 3 次跨半块混合）。

    ⚠ 必须【逐字模拟】C 版 crypto_core.h scrypt_blockmix 的原地别名行为：
    romix 里调用 scrypt_blockmix(X, X)，in/out 同一缓冲：
      out[0:32]  写入后，第 3 步读 in[0:64] 时 0:32 段已是新值；
      out[32:64] 写入后，第 3 步读 in[32:64] 段也是新值……以此类推。
    """
    B = bytes(in128[0:32])
    for r in range(8):
        B = H(B, bytes(in128[r * 16:r * 16 + 16]))   # 8 轮：读原始 in（写发生在后）

    out = bytearray(in128)                            # 就地覆盖
    out[0:32] = B
    out[32:64] = H(B, bytes(in128[64:128]))           # 读原始（未覆盖）
    out[64:96] = H(bytes(out[32:64]), bytes(out[0:64]))
    out[96:128] = H(bytes(out[64:96]), bytes(out[32:96]))
    return bytes(out)


def _integerify(block128: bytes) -> int:
    """取块末尾 8 字节小端 → int（对齐 scrypt_integerify）。"""
    return int.from_bytes(block128[120:128], "little")


def _romix(B: bytes, N: int) -> bytes:
    X = bytearray(B)
    V = []
    for _ in range(N):                 # 第一遍：顺序填充
        V.append(bytes(X))
        X = bytearray(_blockmix(bytes(X)))
    for _ in range(N):                 # 第二遍：随机回访 + XOR
        j = _integerify(bytes(X)) % N
        vj = V[j]
        for k in range(128):
            X[k] ^= vj[k]
        X = bytearray(_blockmix(bytes(X)))
    return bytes(X)


def pbkdf2(pass_: bytes, salt: bytes, iters: int, dklen: int) -> bytes:
    """PBKDF2-HMAC-SHA256（RFC 2898）——与 crypto_core.h 的 pbkdf2_hmac_sha256
    逐字一致：盐块 = salt || be32(blk_idx)，blk_idx 从 1 起。"""
    out = bytearray()
    idx = 1
    while len(out) < dklen:
        u = H(pass_, salt + struct.pack(">I", idx))
        t = bytearray(u)
        for _ in range(iters - 1):
            u = H(pass_, u)
            for k in range(32):
                t[k] ^= u[k]
        out += t
        idx += 1
    return bytes(out[:dklen])


def scrypt_kdf(pass_: bytes, salt: bytes, N: int) -> bytes:
    """口令+盐 → 32B seed。流程与 v7_scrypt_kdf 一致：
    B=PBKDF2(pass,salt,1,128) → X=ROMix(B,N) → seed=PBKDF2(pass,X,1,32)"""
    if N <= 0:
        N = 131072                      # V7_SCRYPT_N 默认 → 16MB
    B = pbkdf2(pass_, salt, 1, 128)
    X = _romix(B, N)
    return pbkdf2(pass_, X, 1, 32)


# ---------------------------------------------------------------- 白盒
def wb_encode(seed: bytes):
    """per-build 随机双射：seed → (table, perm, mask)。
    解码端 = crypto_core.h v7_wb_decode：
      logic = j*8 + (j%8); phys = perm[logic%256]; out[j] = table[phys] ^ mask[logic%256]
    """
    table = bytearray(random.randrange(256) for _ in range(WB_SIZE))   # 含诱饵
    mask = bytearray(random.randrange(256) for _ in range(WB_SIZE))
    perm = list(range(WB_SIZE))
    random.shuffle(perm)
    for j in range(32):
        logic = j * 8 + (j % 8)
        phys = perm[logic % WB_SIZE]
        table[phys] = seed[j] ^ mask[logic % WB_SIZE]
    return bytes(table), bytes(perm), bytes(mask)


def wb_decode(table: bytes, perm: bytes, mask: bytes) -> bytes:
    """与 C 同构（构建端自检用，防编码端笔误）。"""
    out = bytearray(32)
    for j in range(32):
        logic = j * 8 + (j % 8)
        out[j] = table[perm[logic % WB_SIZE]] ^ mask[logic % WB_SIZE]
    return bytes(out)


# ---------------------------------------------------------------- blob 组装
def main(argv):
    passwd = None
    N = 0
    args = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--pass":
            i += 1; passwd = argv[i]
        elif a.startswith("--pass="):
            passwd = a[len("--pass="):]
        elif a == "--scrypt-n":
            i += 1; N = int(argv[i])
        elif a.startswith("--scrypt-n="):
            N = int(a[len("--scrypt-n="):])
        else:
            args.append(a)
        i += 1

    if len(args) != 3:
        sys.stderr.write(
            "用法: python3 v7_embed.py <V6骨架> <bash二进制> <输出> "
            "[--pass '口令'] [--scrypt-n N]\n"
            "  --pass 缺省 = 离线分发模式（seed 随机 + 白盒编码，无需口令）\n")
        return 2

    plain_path, bash_path, out_path = args
    plaintext = open(plain_path, "rb").read()
    bash_bin = open(bash_path, "rb").read()

    salt = os.urandom(16)
    if passwd:
        flags = FLAG_PASSMODE
        seed = scrypt_kdf(passwd.encode("utf-8", "surrogateescape"), salt, N)
        wb = tuple(os.urandom(WB_SIZE) for _ in range(3))   # 诱饵，无语义
    else:
        flags = 0
        seed = os.urandom(32)
        wb = wb_encode(seed)

    # 构建端自检：解码回来必须等于 seed（防编码端笔误）
    if flags & FLAG_PASSMODE == 0 and wb_decode(*wb) != seed:
        sys.stderr.write("内部错误：白盒自检失败\n")
        return 3

    kenc, kmac = v7_keys(seed)
    ct = xor_stream(kenc, plaintext)
    tag = H(kmac, ct)[:16]

    N_out = N if N else 131072
    tail = (ct + tag + salt
            + struct.pack("<I", N_out)
            + wb[0] + wb[1] + wb[2]
            + struct.pack("<I", flags)
            + struct.pack("<I", len(ct) + OVERHEAD))

    with open(out_path, "wb") as f:
        f.write(bash_bin)
        f.write(tail)
    os.chmod(out_path, 0o755)

    mode = "口令模式（scrypt N=%d → %.1fMB）" % (N_out, N_out * 128 / 1048576.0) \
        if flags & FLAG_PASSMODE else "离线分发模式（白盒编码 seed）"
    print("骨架输入   : %s (%d 字节)" % (plain_path, len(plaintext)))
    print("bash 二进制 : %s (%d 字节)" % (bash_path, len(bash_bin)))
    print("加密       : %d 字节密文 + tag 16B（HMAC-SHA256 密钥流）" % len(ct))
    print("分发模式   : %s" % mode)
    print("输出       : %s (%d 字节)" % (out_path, len(bash_bin) + len(tail)))
    if flags & FLAG_PASSMODE:
        print("运行       : echo '内层passkey' | V7_SELF=1 V7_PASS='外层口令' %s /dev/null" % out_path)
    else:
        print("运行       : echo '内层passkey' | V7_SELF=1 %s /dev/null  （无外层口令）" % out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
