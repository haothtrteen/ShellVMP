/* v7core_mksh.c —— V7 密码核心非 static 入口层（mksh 版，路线 C）
 *
 * 对应 bash 线的 v7core.c。**不能直接复用**，原因在 include 的头文件不同：
 *
 *   bash（v7core.c）：#include "crypto_core.h"
 *     build_poc.sh 会把 crypto_core.h 里 5 个函数的 static **去掉**
 *     （VMPacker 要定位 local 符号），v7core.o 于是能直接转发到 v7_* 全局符号。
 *
 *   mksh（本文件）：#include "crypto_isa.h"
 *     那份头**保留 static**（它是 isa_hook.c 的专用副本，避免与 v7core.o
 *     各导出一份同名全局 → duplicate symbol）。static 函数在本编译单元内
 *     可见，所以这里直接包一层非 static 外壳即可 —— 代码一字未改，
 *     只是换个链接可见性。
 *
 * 存在的意义（与 bash 版同三条）：
 *   1) 给 v7_shf_inject.c 提供稳定调用点（它需要跨编译单元调用）；
 *   2) 保证 crypto_isa.h 里的目标函数被引用，不被 -O2 消除
 *      （否则 VMP 定位不到）；
 *   3) 本身不含算法，全部转发 —— VMP 保护的是被转发的那层。
 *
 * mksh 侧不参与 VMP（mksh 线暂无 VMP 需求），故不加 -mgeneral-regs-only 等
 * 特殊 flags；若将来要给 mksh 上 VMP，照 build_poc.sh 的 -func 清单处理即可。
 */

#include <stddef.h>

#include "crypto_isa.h"

/* 口令模式：pass+salt → 32 字节 seed。N=0 用默认。返回 0 成功 / -1 失败。 */
int
v7c_scrypt_kdf(const unsigned char *pass, unsigned int plen,
               const unsigned char *salt, unsigned int slen,
               unsigned char *out, unsigned int outlen,
               unsigned int N)
{
    return v7_scrypt_kdf(pass, (size_t) plen, salt, (size_t) slen,
                         out, (size_t) outlen, (size_t) N);
}

/* seed → kenc[32] / kmac[32] */
void
v7c_keys(const unsigned char seed[32],
         unsigned char kenc[32], unsigned char kmac[32])
{
    v7_keys(seed, kenc, kmac);
}

/* 流式加解密上下文 */
void
v7c_stream_init(v7_stream_ctx *ctx, const unsigned char kenc[32])
{
    v7_stream_init(ctx, kenc);
}

void
v7c_stream_xor(v7_stream_ctx *ctx,
               const unsigned char *in, unsigned char *out, unsigned int n)
{
    v7_stream_xor(ctx, in, out, (size_t) n);
}

void
v7c_stream_wipe(v7_stream_ctx *ctx)
{
    v7_stream_wipe(ctx);
}

/* Encrypt-then-MAC：out[16] = HMAC(kmac, ct) 截断 16 字节 */
void
v7c_tag(const unsigned char kmac[32],
        const unsigned char *ct, unsigned int n,
        unsigned char out[16])
{
    v7_tag(kmac, ct, (size_t) n, out);
}

/* 常数时间比较：相等返回 1，不等返回 0 */
int
v7c_ct_eq(const unsigned char *a, const unsigned char *b, unsigned int n)
{
    return v7_ct_eq(a, b, (size_t) n);
}

/* 离线分发模式：从白盒三表恢复 32 字节 seed */
void
v7c_wb_decode(const unsigned char *wb_table,
              const unsigned char *wb_perm,
              const unsigned char *wb_mask,
              unsigned char out[32])
{
    v7_wb_decode(wb_table, wb_perm, wb_mask, out);
}
