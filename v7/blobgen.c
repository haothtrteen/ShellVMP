/*
 * blobgen.c —— V7 编译端加密器（一次性工具，产物不分发）
 *
 * 用法：
 *   blobgen selftest                                  密码学自测（标准向量）
 *   blobgen enc <seed_hex_64> <in> <out_ct> <out_tag>  加密骨架 → 密文+标签
 *
 * 与 ELF 运行时共用 crypto_core.h —— 同一份代码，两侧公式零分叉可能
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_core.h"

static void hex_dump(const unsigned char *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static int read_file(const char *path, unsigned char **out, size_t *outlen)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    size_t cap = 65536, len = 0, n;

    if (!f)
        return -1;
    buf = (unsigned char *)malloc(cap);
    if (!buf) {
        fclose(f);
        return -1;
    }
    while ((n = fread(buf + len, 1, cap - len, f)) > 0) {
        len += n;
        if (len == cap) {
            cap *= 2;
            buf = (unsigned char *)realloc(buf, cap);
            if (!buf) {
                fclose(f);
                return -1;
            }
        }
    }
    fclose(f);
    *out = buf;
    *outlen = len;
    return 0;
}

static int hex2bin(const char *hex, unsigned char *out, size_t outmax)
{
    size_t hl = strlen(hex), i;

    if (hl % 2 || hl / 2 > outmax)
        return -1;
    for (i = 0; i < hl / 2; i++) {
        unsigned v;
        char lo = hex[2 * i], hi = hex[2 * i + 1];
        int ok = 1;

        v = 0;
        if (lo >= '0' && lo <= '9') v |= (unsigned)(lo - '0') << 4;
        else if (lo >= 'a' && lo <= 'f') v |= (unsigned)(lo - 'a' + 10) << 4;
        else if (lo >= 'A' && lo <= 'F') v |= (unsigned)(lo - 'A' + 10) << 4;
        else ok = 0;
        if (hi >= '0' && hi <= '9') v |= (unsigned)(hi - '0');
        else if (hi >= 'a' && hi <= 'f') v |= (unsigned)(hi - 'a' + 10);
        else if (hi >= 'A' && hi <= 'F') v |= (unsigned)(hi - 'A' + 10);
        else ok = 0;
        if (!ok)
            return -1;
        out[i] = (unsigned char)v;
    }
    return (int)(hl / 2);
}

static int selftest(void)
{
    unsigned char d[32];
    unsigned char key[20];
    int fail = 0;
    int i;

    /* SHA-256("") */
    sha256("", 0, d);
    printf("sha256(\"\")      = ");
    hex_dump(d, 32);
    if (memcmp(d,
        "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
        "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55", 32))
        fail = 1;

    /* SHA-256("abc") */
    sha256("abc", 3, d);
    printf("sha256(\"abc\")   = ");
    hex_dump(d, 32);
    if (memcmp(d,
        "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
        "\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad", 32))
        fail = 1;

    /* HMAC-SHA256 RFC 4231 测试向量 1：key=0x0b×20, msg="Hi There" */
    memset(key, 0x0b, sizeof key);
    hmac_sha256(key, sizeof key, "Hi There", 8, d);
    printf("hmac(tc1)       = ");
    hex_dump(d, 32);
    if (memcmp(d,
        "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b"
        "\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7", 32))
        fail = 1;

    /* 加解密回环：种子→密钥→加密→解密→比对 */
    {
        unsigned char seed[32], kenc[32], kmac[32];
        unsigned char pt[100], ct[100], rt[100], tag[16], tag2[16];

        for (i = 0; i < 32; i++)
            seed[i] = (unsigned char)(i * 7 + 3);
        for (i = 0; i < 100; i++)
            pt[i] = (unsigned char)(i * 13 + 5);
        v7_keys(seed, kenc, kmac);
        v7_crypt(kenc, pt, ct, sizeof pt);
        v7_tag(kmac, ct, sizeof ct, tag);
        v7_tag(kmac, ct, sizeof ct, tag2);
        v7_crypt(kenc, ct, rt, sizeof rt);
        if (memcmp(pt, rt, sizeof pt) || !v7_ct_eq(tag, tag2, 16))
            fail = 1;
        printf("roundtrip       = %s\n", memcmp(pt, rt, sizeof pt) ? "FAIL" : "OK");
    }

    /* PBKDF2 确定性测试：同输入必同输出 */
    {
        unsigned char k1[32], k2[32];

        pbkdf2_hmac_sha256((const unsigned char *)"password", 8,
                           (const unsigned char *)"salt", 4,
                           100, k1, 32);
        pbkdf2_hmac_sha256((const unsigned char *)"password", 8,
                           (const unsigned char *)"salt", 4,
                           100, k2, 32);
        if (memcmp(k1, k2, 32))
            fail = 1;
        printf("pbkdf2 determ   = %s\n", memcmp(k1, k2, 32) ? "FAIL" : "OK");
    }

    /* scrypt-like KDF 确定性 + 内存硬化测试 */
    {
        unsigned char k1[32], k2[32];
        int rc;

        /* N=1024 → 128KB（测试用小 N，生产用默认 16MB） */
        rc = v7_scrypt_kdf((const unsigned char *)"pw", 2,
                           (const unsigned char *)"NaCl", 4,
                           k1, 32, 1024);
        if (rc != 0) {
            printf("scrypt_kdf      = FAIL (rc=%d)\n", rc);
            fail = 1;
        } else {
            v7_scrypt_kdf((const unsigned char *)"pw", 2,
                          (const unsigned char *)"NaCl", 4,
                          k2, 32, 1024);
            if (memcmp(k1, k2, 32))
                fail = 1;
            printf("scrypt_kdf      = %s\n",
                   memcmp(k1, k2, 32) ? "FAIL" : "OK");
        }
    }

    printf("selftest        = %s\n", fail ? "FAIL" : "OK");
    return fail;
}

int main(int argc, char **argv)
{
    unsigned char seed[32], kenc[32], kmac[32], tag[16];
    unsigned char *pt, *ct;
    size_t ptlen;
    FILE *f;

    if (argc == 2 && !strcmp(argv[1], "selftest"))
        return selftest();

    if (argc == 6 && !strcmp(argv[1], "enc")) {
        if (hex2bin(argv[2], seed, sizeof seed) != 32) {
            fprintf(stderr, "blobgen: seed 必须是 64 个十六进制字符\n");
            return 2;
        }
        if (read_file(argv[3], &pt, &ptlen) != 0) {
            fprintf(stderr, "blobgen: 无法读取 %s\n", argv[3]);
            return 2;
        }
        ct = (unsigned char *)malloc(ptlen);
        if (!ct)
            return 2;
        v7_keys(seed, kenc, kmac);
        v7_crypt(kenc, pt, ct, ptlen);
        v7_tag(kmac, ct, ptlen, tag);

        f = fopen(argv[4], "wb");
        if (!f) {
            fprintf(stderr, "blobgen: 无法写 %s\n", argv[4]);
            return 2;
        }
        fwrite(ct, 1, ptlen, f);
        fclose(f);

        f = fopen(argv[5], "wb");
        if (!f) {
            fprintf(stderr, "blobgen: 无法写 %s\n", argv[5]);
            return 2;
        }
        {
            int i;

            for (i = 0; i < 16; i++)
                fprintf(f, "%02x", tag[i]);
        }
        fclose(f);
        return 0;
    }

    /* passkdf：从 stdin 读口令 + salt + N → 输出 32 字节 seed（hex）
     * 用法：echo -n "password" | blobgen passkdf <salt_hex_32> [N]
     * 与 elfrun 运行期的 passkey_derive_seed 用同一份 scrypt-like KDF */
    if (argc >= 3 && !strcmp(argv[1], "passkdf")) {
        unsigned char salt[16];
        unsigned char out[32];
        char passbuf[256];
        size_t passlen;
        size_t N;
        int i;

        if (hex2bin(argv[2], salt, sizeof salt) != 16) {
            fprintf(stderr, "blobgen: salt 必须是 32 个十六进制字符\n");
            return 2;
        }
        N = (argc >= 4) ? (size_t)strtoul(argv[3], NULL, 10) : 0;

        /* 从 stdin 读口令（去尾换行） */
        passlen = fread(passbuf, 1, sizeof(passbuf) - 1, stdin);
        while (passlen > 0 && (passbuf[passlen - 1] == '\n' ||
               passbuf[passlen - 1] == '\r'))
            passlen--;
        if (passlen == 0) {
            fprintf(stderr, "blobgen: 口令为空\n");
            return 2;
        }

        if (v7_scrypt_kdf((const unsigned char *)passbuf, passlen,
                          salt, 16, out, 32, N) != 0) {
            fprintf(stderr, "blobgen: KDF 失败\n");
            memset(passbuf, 0, sizeof passbuf);
            return 2;
        }
        memset(passbuf, 0, sizeof passbuf);

        for (i = 0; i < 32; i++)
            printf("%02x", out[i]);
        printf("\n");
        memset(out, 0, 32);
        return 0;
    }

    /* wbenc：白盒密钥编码。输入 32 字节 seed → 输出 3 个 256 字节表（hex）
     * 用法：blobgen wbenc <seed_hex_64>
     * 输出三行：wb_table_hex / wb_perm_hex / wb_mask_hex
     * 与 elfrun 运行期的 v7_wb_decode 用同一份编码/解码逻辑 */
    if (argc == 3 && !strcmp(argv[1], "wbenc")) {
        unsigned char seed[32];
        unsigned char wb_table[V7_WB_TABLE_SIZE];
        unsigned char wb_perm[V7_WB_TABLE_SIZE];
        unsigned char wb_mask[V7_WB_TABLE_SIZE];
        int used[V7_WB_TABLE_SIZE];
        int i, j;

        if (hex2bin(argv[2], seed, sizeof seed) != 32) {
            fprintf(stderr, "blobgen: seed 必须是 64 个十六进制字符\n");
            return 2;
        }

        /* 初始化 */
        memset(used, 0, sizeof used);
        for (i = 0; i < V7_WB_TABLE_SIZE; i++) {
            wb_table[i] = (unsigned char)(rand() & 0xff);  /* 诱饵随机字节 */
            wb_mask[i] = (unsigned char)(rand() & 0xff);
            wb_perm[i] = (unsigned char)i;  /* 初始恒等 */
        }

        /* 生成随机置换表（Fisher-Yates 洗牌） */
        for (i = V7_WB_TABLE_SIZE - 1; i > 0; i--) {
            int j2 = rand() % (i + 1);
            unsigned char tmp = wb_perm[i];

            wb_perm[i] = wb_perm[j2];
            wb_perm[j2] = tmp;
        }

        /* 把 seed 字节编码到表中随机位置 */
        for (j = 0; j < 32; j++) {
            unsigned logic_pos = (unsigned)(j * 8 + (j % 8));
            unsigned phys_pos = wb_perm[logic_pos % V7_WB_TABLE_SIZE];

            wb_table[phys_pos] = seed[j] ^ wb_mask[logic_pos % V7_WB_TABLE_SIZE];
        }

        /* 输出三个表（hex） */
        for (i = 0; i < V7_WB_TABLE_SIZE; i++)
            printf("%02x", wb_table[i]);
        printf("\n");
        for (i = 0; i < V7_WB_TABLE_SIZE; i++)
            printf("%02x", wb_perm[i]);
        printf("\n");
        for (i = 0; i < V7_WB_TABLE_SIZE; i++)
            printf("%02x", wb_mask[i]);
        printf("\n");

        memset(seed, 0, 32);
        memset(wb_table, 0, V7_WB_TABLE_SIZE);
        memset(wb_perm, 0, V7_WB_TABLE_SIZE);
        memset(wb_mask, 0, V7_WB_TABLE_SIZE);
        return 0;
    }

    fprintf(stderr, "usage: blobgen selftest | enc <seedhex> <in> <out_ct> <out_tag> | passkdf <salt_hex> [N] | wbenc <seed_hex>\n");
    return 2;
}
