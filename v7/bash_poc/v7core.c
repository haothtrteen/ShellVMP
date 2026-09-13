/* v7core.c —— V7 密码核心（r12：对齐路线 A）
 *
 * 本文件独立编译，特殊 flags（由 build_poc.sh 注入 Makefile）：
 *   -mgeneral-regs-only               全 GPR（VMPacker 的 VM 无 NEON 寄存器）
 *   -fno-optimize-sibling-calls       禁尾跳（VMPacker 要求函数区间闭合）
 *
 * r12 变更：不再自造 RC4 + HMAC 链 KDF，改为 #include "crypto_core.h"
 * 直接复用路线 A（elfrun/blobgen）已验证过的同一套实现：
 *   · v7_scrypt_kdf  scrypt-like ROMix（N=131072 → 16MB，内存硬度）
 *   · v7_keys        seed → kenc/kmac（HMAC 标签派生）
 *   · v7_keystream   HMAC-SHA256 CTR 密钥流（32B/块）—— 取代 RC4
 *   · v7_tag         Encrypt-then-MAC 标签（16B）+ v7_ct_eq 常数时间比对
 *   · v7_wb_decode   白盒 seed 解码（离线分发模式）
 * 这么做的直接好处：C 端与 Python 端不再是"两套代码对拍"，而是与 A 同一实现。
 *
 * VMP 目标函数（build_poc.sh --vmp 时按名字定位）：
 *   v7_scrypt_kdf / v7_keys / v7_keystream / v7_tag / v7_wb_decode
 * 注意：这些在 crypto_core.h 里是 static，必须先有引用才不会被 -O2 优化掉——
 * 下面的 v7c_* 非 static 入口正是为此存在（同时也是 zread.c 的调用点）。
 */

#include <stdlib.h>   /* malloc / free（scrypt 的 V 数组需要堆内存） */
#include <stddef.h>

#include "crypto_core.h"

/* =========================================================================
 * 非 static 入口层
 * 作用有二：
 *   1) 保证上列 static 目标函数被引用，不会被 -O2 消除（否则 VMP 定位不到）；
 *   2) 给 zread.c 提供稳定调用点。
 * 本身不含算法，全部转发到 crypto_core.h —— VMP 保护的是被转发的那层。
 * ========================================================================= */

/* 口令模式：pass+salt → 32 字节 seed。N=0 用默认（131072 → 16MB）。
 * 返回 0 成功，-1 失败（通常是内存分配失败） */
int
v7c_scrypt_kdf (const unsigned char *pass, unsigned int plen,
                const unsigned char *salt, unsigned int slen,
                unsigned char *out, unsigned int outlen,
                unsigned int N)
{
  return v7_scrypt_kdf (pass, (size_t) plen, salt, (size_t) slen,
                        out, (size_t) outlen, (size_t) N);
}

/* seed → kenc[32] / kmac[32] */
void
v7c_keys (const unsigned char seed[32],
          unsigned char kenc[32], unsigned char kmac[32])
{
  v7_keys (seed, kenc, kmac);
}

/* 流式加解密上下文（分段：任何时刻只有一小段明文驻留内存） */
void
v7c_stream_init (v7_stream_ctx *ctx, const unsigned char kenc[32])
{
  v7_stream_init (ctx, kenc);
}

void
v7c_stream_xor (v7_stream_ctx *ctx,
                const unsigned char *in, unsigned char *out, unsigned int n)
{
  v7_stream_xor (ctx, in, out, (size_t) n);
}

void
v7c_stream_wipe (v7_stream_ctx *ctx)
{
  v7_stream_wipe (ctx);
}

/* Encrypt-then-MAC：out[16] = HMAC(kmac, ct) 截断 16 字节 */
void
v7c_tag (const unsigned char kmac[32],
         const unsigned char *ct, unsigned int n,
         unsigned char out[16])
{
  v7_tag (kmac, ct, (size_t) n, out);
}

/* 常数时间比较：相等返回 1，不等返回 0（crypto_core.h 的 v7_ct_eq 语义） */
int
v7c_ct_eq (const unsigned char *a, const unsigned char *b, unsigned int n)
{
  return v7_ct_eq (a, b, (size_t) n);
}

/* 离线分发模式：从白盒三表恢复 32 字节 seed */
void
v7c_wb_decode (const unsigned char *wb_table,
               const unsigned char *wb_perm,
               const unsigned char *wb_mask,
               unsigned char out[32])
{
  v7_wb_decode (wb_table, wb_perm, wb_mask, out);
}
