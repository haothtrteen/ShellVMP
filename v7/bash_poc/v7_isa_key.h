/* 自动生成，勿手改 —— 由 tools/v7_isa.py emit-key 生成。
 *
 * r21：ISA 第一层表的**主密钥**。不以连续明文存在于 rodata：
 *   32B 拆 8×u32，每份与随机掩码异或后分两串（_x / _m）存放。
 *   单看任一一串都是无意义随机数据，必须二者相异或才得主密钥。
 * 运行期由 v7_isa_master()（VMP 保护）现场重组后立即擦除栈副本。
 *
 * 换掉本文件 = 换密钥 = 既有表全部作废（解密失败 → ISA 静默空转）。
 * 与 v7_isa_syms.h 同属「一次编 bash 生成、之后固定」的配对产物。 */
#ifndef V7_ISA_KEY_H
#define V7_ISA_KEY_H

static const unsigned int v7_isa_km_x[8] = {
    0xa973e0beu, 0x5731d289u, 0x500eed0cu, 0x485bbc93u,
    0x4d0b942au, 0xa52d9026u, 0xfc0ef031u, 0x376922ddu,
};

static const unsigned int v7_isa_km_m[8] = {
    0x1f89adb6u, 0x8c32c4b4u, 0xa3a92e6cu, 0xb2d46297u,
    0x8bf44be8u, 0x0a389d63u, 0xfadaafd6u, 0x66b4dfefu,
};

#endif /* V7_ISA_KEY_H */
