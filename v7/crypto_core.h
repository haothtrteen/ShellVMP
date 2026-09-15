/*
 * crypto_core.h —— V7 ELF 保护层共享密码学核心
 *
 * 编译端（blobgen）与运行端（ELF runtime）共用同一份代码：
 *   - 杜绝"两侧公式分叉"这类 shell 版踩过的坑（本会话刚修过 rt/rc 分叉）
 *   - 纯 C99 零外部依赖：glibc/musl/bionic(Termux clang) 通吃
 *
 * 方案：Encrypt-then-MAC（与 V6 哲学一致）
 *   K_enc = HMAC-SHA256(seed, "V7ENC")      会话加密密钥
 *   K_mac = HMAC-SHA256(seed, "V7MAC")      会话 MAC 密钥（密钥分离）
 *   流密钥块 i = HMAC-SHA256(K_enc, i 的 8 字节大端)   → CTR 式 XOR 流
 *   tag = HMAC-SHA256(K_mac, ct) 截断 16 字节
 *
 * 说明：seed 内嵌于 ELF（与 shc 同级可见），本层目标不是密钥保密，
 * 而是 (a) 明文不出现在 strings/grep 可见层 (b) 篡改即拒跑。
 * 真正的机密性由内层 V6 执行绑定密钥链承担 —— dump 到的只是密文骨架。
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * SPDX-FileCopyrightText: 2026 haothtrteen <2557976190@qq.com>
 * AGPLv3 双许可——闭源商用需另获授权，见 LICENSE.COMMERCIAL 
 */

#ifndef CRYPTO_CORE_H
#define CRYPTO_CORE_H

#include <stdint.h>
#include <string.h>

/* ==================== per-build 随机化常量 ====================
 *
 * 背景（r10 已知弱点）：默认标签 "V7ENC" / "V7MAC" 以明文躺在 .rodata，
 * 攻击者执行 `strings x.elf | grep V7` 就能在几秒内定位到 v7_keys，
 * 进而拿到整条信任链的根。r10 的 anti-disassembly 抹掉了符号表，
 * 却没抹掉这两个"语义路标"。
 *
 * 对策：构建时生成随机标签并注入（加密端 blobgen 与运行端 elfrun 用同一个）。
 *   - 默认仍是 "V7ENC"/"V7MAC"，保证既有产物字节级兼容；
 *   - V7_RAND_LABEL=1 时替换为随机串 —— 跨样本的通用检测/yara 规则失效；
 *   - V7_LABEL_OBF=1 时进一步把标签以 XOR 混淆的字节数组存储，
 *     运行时再解开，rodata 里连可打印串都没有（单样本 strings 也失效）。
 *
 * 注意：标签参与密钥派生，改了标签 = 换了密钥。
 * 不同标签的两个产物**互不兼容**（这是特性，不是 bug）。
 * ================================================================ */

#ifndef V7_LABEL_ENC
#  define V7_LABEL_ENC "V7ENC"
#endif
#ifndef V7_LABEL_MAC
#  define V7_LABEL_MAC "V7MAC"
#endif
/* 落盘兜底链的临时文件前缀（默认 ".v7x." 同样是个显眼路标） */
#ifndef V7_TMP_PREFIX
#  define V7_TMP_PREFIX ".v7x."
#endif

#if defined(V7_LABEL_OBF)
/* L2：标签不入 .rodata 明文。
 * 数组内容 + 掩码由构建脚本生成，运行时 XOR 解开到栈上，用完即焚。
 * 宏展开后形如：{ 0x39, 0x2b, ... } / { 0x6a, 0x5f, ... }
 */
#  ifndef V7_LB_ENC_OBF
#    define V7_LB_ENC_OBF { 'V'^0x5a, '7'^0x5a, 'E'^0x5a, 'N'^0x5a, 'C'^0x5a }
#  endif
#  ifndef V7_LB_MAC_OBF
#    define V7_LB_MAC_OBF { 'V'^0x5a, '7'^0x5a, 'M'^0x5a, 'A'^0x5a, 'C'^0x5a }
#  endif
#  ifndef V7_LB_XOR
#    define V7_LB_XOR 0x5a
#  endif
#  ifndef V7_LB_ENC_LEN
#    define V7_LB_ENC_LEN 5
#  endif
#  ifndef V7_LB_MAC_LEN
#    define V7_LB_MAC_LEN 5
#  endif

/* 把混淆标签解开到调用者提供的缓冲区（栈上），返回长度 */
static size_t v7_label_dec(const unsigned char *obf, size_t n,
                           unsigned char x, unsigned char *out)
{
    size_t i;
    for (i = 0; i < n; i++)
        out[i] = (unsigned char)(obf[i] ^ x);
    out[n] = 0;
    return n;
}
#endif /* V7_LABEL_OBF */

/* ============================ SHA-256 ============================ */

typedef struct {
    uint32_t     h[8];
    uint64_t     len;      /* 已处理总字节数 */
    unsigned char buf[64];
    unsigned     buflen;
} sha256_ctx;

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_init(sha256_ctx *c)
{
    c->h[0] = 0x6a09e667; c->h[1] = 0xbb67ae85;
    c->h[2] = 0x3c6ef372; c->h[3] = 0xa54ff53a;
    c->h[4] = 0x510e527f; c->h[5] = 0x9b05688c;
    c->h[6] = 0x1f83d9ab; c->h[7] = 0x5be0cd19;
    c->len = 0;
    c->buflen = 0;
}

static void sha256_block(sha256_ctx *c, const unsigned char *p)
{
    uint32_t w[64];
    uint32_t a, b, d, e, f, g, h, ch;
    uint32_t cc, t1, t2, S0, S1;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) |
               ((uint32_t)p[4 * i + 2] << 8) | (uint32_t)p[4 * i + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROTR32(w[i - 15], 7) ^ ROTR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROTR32(w[i - 2], 17) ^ ROTR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g  = c->h[6]; h = c->h[7];
    for (i = 0; i < 64; i++) {
        S1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
        ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + K256[i] + w[i];
        S0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
        {
            uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
            t2 = S0 + maj;
        }
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g;  c->h[7] += h;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t n)
{
    const unsigned char *p = (const unsigned char *)data;

    c->len += n;
    if (c->buflen) {
        size_t take = 64 - c->buflen;
        if (take > n)
            take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += (unsigned)take;
        p += take;
        n -= take;
        if (c->buflen == 64) {
            sha256_block(c, c->buf);
            c->buflen = 0;
        }
    }
    while (n >= 64) {
        sha256_block(c, p);
        p += 64;
        n -= 64;
    }
    if (n) {
        memcpy(c->buf, p, n);
        c->buflen = (unsigned)n;
    }
}

static void sha256_final(sha256_ctx *c, unsigned char out[32])
{
    uint64_t bits = c->len * 8;
    unsigned char pad[72];
    unsigned char lenb[8];
    size_t padlen;
    int i;

    for (i = 0; i < 8; i++)
        lenb[i] = (unsigned char)(bits >> (56 - 8 * i));
    padlen = (c->buflen < 56) ? (56 - c->buflen) : (120 - c->buflen);
    memset(pad, 0, sizeof pad);
    pad[0] = 0x80;
    sha256_update(c, pad, padlen);
    sha256_update(c, lenb, 8);
    for (i = 0; i < 8; i++) {
        out[4 * i]     = (unsigned char)(c->h[i] >> 24);
        out[4 * i + 1] = (unsigned char)(c->h[i] >> 16);
        out[4 * i + 2] = (unsigned char)(c->h[i] >> 8);
        out[4 * i + 3] = (unsigned char)(c->h[i]);
    }
}

static void sha256(const void *data, size_t n, unsigned char out[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, n);
    sha256_final(&c, out);
}

/* ========================== HMAC-SHA256 ========================== */

static void hmac_sha256(const unsigned char *key, size_t keylen,
                        const void *msg, size_t msglen,
                        unsigned char out[32])
{
    unsigned char k[64], pad[64], inner[32];
    sha256_ctx c;
    size_t i;

    memset(k, 0, 64);
    if (keylen > 64)
        sha256(key, keylen, k);
    else
        memcpy(k, key, keylen);

    for (i = 0; i < 64; i++)
        pad[i] = k[i] ^ 0x36;
    sha256_init(&c);
    sha256_update(&c, pad, 64);
    sha256_update(&c, msg, msglen);
    sha256_final(&c, inner);

    for (i = 0; i < 64; i++)
        pad[i] = k[i] ^ 0x5c;
    sha256_init(&c);
    sha256_update(&c, pad, 64);
    sha256_update(&c, inner, 32);
    sha256_final(&c, out);

    memset(k, 0, 64);
    memset(pad, 0, 64);
    memset(inner, 0, 32);
}

/* ==================== V7 blob 密钥编排与操作 ==================== */

/* r10+: V7_NOINLINE —— 让 -O2 不要把关键函数内联进 main。
 * 默认关闭（保持现状：函数被内联、更难被静态定位）。
 * 需要把函数交给 VMP / 代码虚拟化工具逐个体保护时，编译时加 -DV7_NOINLINE=1，
 * 这样 v7_keys / v7_crypt / v7_tag / v7_wb_decode / ... 会各自保留为独立的
 * sub_xxxxxx，IDA 里能精确勾选，而不是全部糊在 main 里。
 */
#if defined(V7_NOINLINE)
#  if defined(__GNUC__) || defined(__clang__)
#    define V7_NOINLINE_ATTR __attribute__((noinline))
#  else
#    define V7_NOINLINE_ATTR
#  endif
#else
#  define V7_NOINLINE_ATTR
#endif

V7_NOINLINE_ATTR static void v7_keys(const unsigned char seed[32],
                    unsigned char kenc[32], unsigned char kmac[32])
{
#if defined(V7_LABEL_OBF)
    /* 标签在栈上解开，用完立刻擦掉 —— rodata 里没有可打印的副本 */
    static const unsigned char _le[] = V7_LB_ENC_OBF;
    static const unsigned char _lm[] = V7_LB_MAC_OBF;
    unsigned char le[V7_LB_ENC_LEN + 1], lm[V7_LB_MAC_LEN + 1];
    v7_label_dec(_le, V7_LB_ENC_LEN, (unsigned char)V7_LB_XOR, le);
    v7_label_dec(_lm, V7_LB_MAC_LEN, (unsigned char)V7_LB_XOR, lm);
#else
    const unsigned char *le = (const unsigned char *)V7_LABEL_ENC;
    const unsigned char *lm = (const unsigned char *)V7_LABEL_MAC;
#endif
#if defined(V7_LABEL_OBF)
    hmac_sha256(seed, 32, le, V7_LB_ENC_LEN, kenc);
    hmac_sha256(seed, 32, lm, V7_LB_MAC_LEN, kmac);
#else
    hmac_sha256(seed, 32, le, sizeof(V7_LABEL_ENC) - 1, kenc);
    hmac_sha256(seed, 32, lm, sizeof(V7_LABEL_MAC) - 1, kmac);
#endif
#if defined(V7_LABEL_OBF)
    memset(le, 0, sizeof le);
    memset(lm, 0, sizeof lm);
#endif
}

/* 流密钥块 i：HMAC(K_enc, i 的 8 字节大端) —— 32 字节/块 */
V7_NOINLINE_ATTR static void v7_keystream(const unsigned char kenc[32], uint64_t i,
                         unsigned char out[32])
{
    unsigned char ctr[8];
    int j;

    for (j = 0; j < 8; j++)
        ctr[j] = (unsigned char)((i >> (56 - 8 * j)) & 0xff);
    hmac_sha256(kenc, 32, ctr, 8, out);
}

/* XOR 对称：加解密同一函数 */
V7_NOINLINE_ATTR static void v7_crypt(const unsigned char kenc[32],
                     const unsigned char *in, unsigned char *out, size_t n)
{
    uint64_t blk = 0;
    size_t off = 0;
    unsigned char ks[32];

    while (off < n) {
        size_t chunk = (n - off < 32) ? (n - off) : 32;
        size_t t;

        v7_keystream(kenc, blk++, ks);
        for (t = 0; t < chunk; t++)
            out[off + t] = in[off + t] ^ ks[t];
        off += chunk;
    }
    memset(ks, 0, 32);
}

/* ---- 流式解密上下文（分段解密：任何时刻只有一小段明文驻留内存）----
 * 用法：
 *   v7_stream_ctx ctx;
 *   v7_stream_init(&ctx, kenc);            // 初始化（kenc 用后由调用方清零）
 *   v7_stream_xor(&ctx, ct_chunk, out, n); // 解密一段 → 写出 → 调用方抹除 out
 *   v7_stream_wipe(&ctx);                  // 用完清零
 * 密钥流块索引随调用自动推进，与 v7_crypt 逐比特一致 */
typedef struct {
    unsigned char kenc[32];
    uint64_t      blk;       /* 当前密钥流块索引 */
    unsigned char ks[32];    /* 当前块密钥流 */
    size_t        ks_pos;    /* ks 中已消费到的偏移（0-31） */
} v7_stream_ctx;

V7_NOINLINE_ATTR static void v7_stream_init(v7_stream_ctx *ctx, const unsigned char kenc[32])
{
    memcpy(ctx->kenc, kenc, 32);
    ctx->blk = 0;
    ctx->ks_pos = 32;  /* 迫使首次调用时生成第一块 */
}

V7_NOINLINE_ATTR static void v7_stream_xor(v7_stream_ctx *ctx,
                          const unsigned char *in, unsigned char *out, size_t n)
{
    size_t off = 0;
    while (off < n) {
        if (ctx->ks_pos >= 32) {
            v7_keystream(ctx->kenc, ctx->blk++, ctx->ks);
            ctx->ks_pos = 0;
        }
        out[off] = in[off] ^ ctx->ks[ctx->ks_pos];
        ctx->ks_pos++;
        off++;
    }
}

static void v7_stream_wipe(v7_stream_ctx *ctx)
{
    memset(ctx->kenc, 0, 32);
    memset(ctx->ks, 0, 32);
    ctx->blk = 0;
    ctx->ks_pos = 0;
}

/* Encrypt-then-MAC：tag = HMAC(K_mac, ct) 截断 16 字节 */
V7_NOINLINE_ATTR static void v7_tag(const unsigned char kmac[32],
                   const unsigned char *ct, size_t n,
                   unsigned char out[16])
{
    unsigned char mac[32];

    hmac_sha256(kmac, 32, ct, n, mac);
    memcpy(out, mac, 16);
    memset(mac, 0, 32);
}

/* 常数时间比较（防时序侧信道） */
static int v7_ct_eq(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char d = 0;
    size_t i;

    for (i = 0; i < n; i++)
        d |= (unsigned char)(a[i] ^ b[i]);
    return d == 0;
}

/* ==================== 白盒密钥编码（r10 P1+） ====================
 *
 * 目标：32 字节 seed 不再以连续明文数组存在于 ELF .rodata 中。
 * 改为通过 per-build 随机双射分散到 256 字节查找表中——攻击者
 * 不能 grep/模式匹配出 seed，必须对表做代数分析才能恢复。
 *
 * 原理（per-build affine encoding）：
 *   编码端：生成随机 seed[32] + 随机置换 perm[256] + 随机 mask[256]
 *     对每个 seed 字节 s[j]（j=0..31）：
 *       encoded[perm[j*8 + (j%8)]] = s[j] ^ mask[j*8 + (j%8)]
 *     表中其余位置填随机字节（诱饵）
 *   解码端：逆运算恢复 seed
 *
 * 安全性：非完整白盒 AES（无 Chow 方案的类型 II/III 编码），但把
 * "grep 连续 32 字节"（秒级）变成"分析 256 字节表的双射结构"。
 * 配合 per-build 随机化：每个产物的表不同，通用脱壳机失效。
 *
 * 代价：ELF .rodata 增加 256+256=512 字节（可忽略）。
 * seed 恢复需 32 次查表+XOR（纳秒级，零运行时影响）。
 */

/* WB_TABLE_SIZE：编码表大小（256 字节 = 16 倍 seed 长度，含诱饵） */
#define V7_WB_TABLE_SIZE 256

/* 白盒密钥解码：从编码表 + 置换表 + mask 恢复 32 字节 seed
 * wb_table：256 字节编码表（含 seed 字节分散 + 诱饵随机字节）
 * wb_perm：256 字节置换表（位置映射：逻辑位置 → 物理位置）
 * wb_mask：256 字节 XOR mask
 * out：输出 32 字节 seed */
V7_NOINLINE_ATTR static void v7_wb_decode(const unsigned char *wb_table,
                         const unsigned char *wb_perm,
                         const unsigned char *wb_mask,
                         unsigned char out[32])
{
    int j;

    for (j = 0; j < 32; j++) {
        /* 逻辑位置 = j*8 + (j%8)，物理位置 = perm[逻辑位置] */
        unsigned logic_pos = (unsigned)(j * 8 + (j % 8));
        unsigned phys_pos = wb_perm[logic_pos % V7_WB_TABLE_SIZE];

        out[j] = wb_table[phys_pos] ^ wb_mask[logic_pos % V7_WB_TABLE_SIZE];
    }
}

/* ==================== PBKDF2-HMAC-SHA256 ==================== */
/* RFC 2898。复用已有 hmac_sha256。用于口令派生密钥的基线 KDF，
 * 以及 scrypt-like KDF 的输入/输出变换 */

static void pbkdf2_hmac_sha256(const unsigned char *pass, size_t passlen,
                               const unsigned char *salt, size_t saltlen,
                               unsigned iter, unsigned char *out, size_t outlen)
{
    unsigned char U[32], T[32];
    unsigned char *salt_block;
    size_t salt_block_len = saltlen + 4;
    uint32_t blk_idx;
    size_t off = 0;
    unsigned i;
    int j;

    salt_block = (unsigned char *)malloc(salt_block_len);
    if (!salt_block)
        return;
    memcpy(salt_block, salt, saltlen);

    blk_idx = 1;
    while (off < outlen) {
        /* U_1 = HMAC(pass, salt || INT_32_BE(blk_idx)) */
        salt_block[saltlen]     = (unsigned char)(blk_idx >> 24);
        salt_block[saltlen + 1] = (unsigned char)(blk_idx >> 16);
        salt_block[saltlen + 2] = (unsigned char)(blk_idx >> 8);
        salt_block[saltlen + 3] = (unsigned char)(blk_idx);
        hmac_sha256(pass, passlen, salt_block, salt_block_len, U);
        memcpy(T, U, 32);

        /* U_2 .. U_c */
        for (i = 1; i < iter; i++) {
            hmac_sha256(pass, passlen, U, 32, U);
            for (j = 0; j < 32; j++)
                T[j] ^= U[j];
        }

        /* 输出 */
        {
            size_t copylen = (off + 32 <= outlen) ? 32 : (outlen - off);

            memcpy(out + off, T, copylen);
            off += copylen;
        }
        blk_idx++;
    }
    memset(U, 0, 32);
    memset(T, 0, 32);
    memset(salt_block, 0, salt_block_len);
    free(salt_block);
}

/* ==================== scrypt-like 内存硬化 KDF ====================
 *
 * 目标：口令派生密钥时引入内存硬度（memory-hardness），使 GPU/ASIC
 * 并行爆破需要大显存——纯 PBKDF2 的迭代数可被并行硬件线性加速，
 * 而 scrypt 的 ROMix 强制顺序访问 N×128 字节内存。
 *
 * 流程（简化 scrypt）：
 *   1. B = PBKDF2(pass, salt, 1) → 128 字节初始块
 *   2. V = MFcrypt(B, N)         → N×128 字节内存填充 + 随机回访
 *   3. K = PBKDF2(pass, V, 1)    → 最终密钥
 *
 * MFcrypt（ROMix 核心逻辑）：
 *   for i in 0..N-1: V[i] = scryptBlockMix(V[i-1])  顺序填充
 *   for i in 0..N-1: j = integerify(V[i]) % N; V[i+1] = scryptBlockMix(V[j] XOR V[i])
 *   → 第二遍随机访问 N 个块，强制攻击者也分配 N×128 字节
 *
 * 简化点（仍保留内存硬度核心）：
 *   - scryptBlockMix 用 HMAC-SHA256 链代替 Salsa20（复用已有原语）
 *   - N 参数控制内存（N×128 字节），默认 N=131072 → 16MB
 *   - integerify 取块末尾 8 字节小端 → uint64 → % N
 *
 * 安全性：非完整 scrypt（无 Salsa20 核心混合），但内存访问模式
 * 与 scrypt 相同——攻击者必须分配 N×128 字节并执行 N 次随机访问。
 * 对比 PBKDF2 的纯 CPU 迭代，GPU 并行度被内存带宽限制。
 */

#define V7_SCRYPT_BLOCK 128   /* 每块 128 字节（4×SHA-256 输出） */
#define V7_SCRYPT_R 8          /* scryptBlockMix 轮数 */
#define V7_SCRYPT_N 131072     /* N=2^17 → 16MB 内存（默认） */
#define V7_SCRYPT_P 1          /* 并行参数（简化版固定 1） */

/* scryptBlockMix：输入 128 字节 → 输出 128 字节
 * 简化实现：4 轮 HMAC-SHA256 链式混合 */
static void scrypt_blockmix(const unsigned char *in, unsigned char *out)
{
    unsigned char B[32];
    int r;

    memcpy(B, in, 32);
    for (r = 0; r < V7_SCRYPT_R; r++) {
        /* B = HMAC(B, in_block[r]) — 链式混合 */
        hmac_sha256(B, 32, in + (r * 16), 16, B);
    }
    /* 输出 = HMAC 链的 4 个 32 字节块 */
    memcpy(out, B, 32);
    hmac_sha256(B, 32, in + 64, 64, out + 32);
    hmac_sha256(out + 32, 32, in, 64, out + 64);
    hmac_sha256(out + 64, 32, in + 32, 64, out + 96);
    memset(B, 0, 32);
}

/* integerify：从块中提取一个整数索引用于随机回访 */
static uint64_t scrypt_integerify(const unsigned char *block)
{
    /* 取块末尾 8 字节小端 → uint64 */
    uint64_t v = 0;
    int j;

    for (j = 0; j < 8; j++)
        v |= (uint64_t)block[V7_SCRYPT_BLOCK - 8 + j] << (8 * j);
    return v;
}

/* ROMix：在 N×128 字节内存上做两遍——顺序填充 + 随机回访 */
static void scrypt_romix(unsigned char *B, size_t N,
                         unsigned char *V, unsigned char *X)
{
    size_t i;
    uint64_t j;
    unsigned char tmp[V7_SCRYPT_BLOCK];

    memcpy(X, B, V7_SCRYPT_BLOCK);

    /* 第一遍：顺序填充 V[0..N-1] */
    for (i = 0; i < N; i++) {
        memcpy(V + i * V7_SCRYPT_BLOCK, X, V7_SCRYPT_BLOCK);
        scrypt_blockmix(X, X);
    }

    /* 第二遍：随机回访 + XOR + blockmix */
    for (i = 0; i < N; i++) {
        j = scrypt_integerify(X) % N;
        {
            unsigned char *Vj = V + (size_t)j * V7_SCRYPT_BLOCK;
            int k;

            for (k = 0; k < V7_SCRYPT_BLOCK; k++)
                X[k] ^= Vj[k];
        }
        scrypt_blockmix(X, X);
    }
    memset(tmp, 0, V7_SCRYPT_BLOCK);
}

/* scrypt-like KDF 主函数
 * pass/passlen：口令
 * salt/saltlen：盐（随产物内嵌，每次随机）
 * out：输出密钥缓冲
 * outlen：输出长度（通常 32 字节，与 V7 seed 同长）
 * N：内存参数（块数，每块 128 字节；默认 V7_SCRYPT_N=131072 → 16MB）
 *    传 0 用默认值
 * 返回 0 成功，-1 失败（内存分配失败） */
V7_NOINLINE_ATTR static int v7_scrypt_kdf(const unsigned char *pass, size_t passlen,
                         const unsigned char *salt, size_t saltlen,
                         unsigned char *out, size_t outlen,
                         size_t N)
{
    unsigned char B[V7_SCRYPT_BLOCK];
    unsigned char *V, *X;

    if (N == 0)
        N = V7_SCRYPT_N;

    /* 1. B = PBKDF2(pass, salt, 1) → 128 字节 */
    pbkdf2_hmac_sha256(pass, passlen, salt, saltlen, 1, B, V7_SCRYPT_BLOCK);

    /* 2. V = MFcrypt(B, N) */
    V = (unsigned char *)malloc(N * V7_SCRYPT_BLOCK);
    X = (unsigned char *)malloc(V7_SCRYPT_BLOCK);
    if (!V || !X) {
        memset(B, 0, V7_SCRYPT_BLOCK);
        free(V);
        free(X);
        return -1;
    }
    scrypt_romix(B, N, V, X);

    /* 3. K = PBKDF2(pass, B_final=X, 1) → 最终密钥 */
    pbkdf2_hmac_sha256(pass, passlen, X, V7_SCRYPT_BLOCK, 1, out, outlen);

    /* 清零所有敏感中间状态 */
    memset(B, 0, V7_SCRYPT_BLOCK);
    memset(V, 0, N * V7_SCRYPT_BLOCK);
    memset(X, 0, V7_SCRYPT_BLOCK);
    free(V);
    free(X);
    return 0;
}

#endif /* CRYPTO_CORE_H */
