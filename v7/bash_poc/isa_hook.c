/* isa_hook.c —— r16 四层随机化表 C 端（VMP 目标单元，r16 立项见 R10_CHANGES G.1.5）
 *
 * 职责：payload 中经 tools/v7_isa.py 改写的随机名，在此还原为真名后
 * 交回 bash 正常分派（builtin/external/保留字）。**方向 alias→orig**：
 * bash 内置分派器看到的就是原名，无需触碰 builtin 注册表。
 *
 * 表来源（r21）：
 *   环境变量 V7_ISA_TABLE 指向 **V7IST 加密表**（tools/v7_isa.py gen 产物）。
 *   磁盘上永远是密文；本文件读入后在**堆里解开**、用完即焚 —— 明文表
 *   在任何时刻都不落盘。无表 / 解密失败 / MAC 不匹配 → 全部翻译函数空转，
 *   零行为差异（fail-closed：宁可退化成未魔改 bash，也不用半张坏表）。
 *   正式形态（后续迭代）：blob 配方头内嵌，v7_init 直接传内存指针。
 *
 * VMP 目标（--vmp 时纳入保护清单，见 tools/vmp_targets.py）：
 *   v7_isa_init / v7_isa_translate_cmd / v7_isa_translate_kw
 *   v7_isa_master / v7_isa_derive            （r21 表解密主密钥链）
 *   （表数据 + 翻译逻辑；表参与 blob 层 HMAC，篡改即拒跑）
 *
 * 插桩点（isa_hook.py 负责 patch，幂等）：
 *   execute_cmd.c execute_simple_command：命令词展开后、首个分派读取前
 *     → v7_isa_translate_cmd(&words->word->word)（单点覆盖
 *       find_special_builtin / find_function / find_shell_builtin / execve 全路径）
 *   y.tab.c CHECK_FOR_RESERVED_WORD 宏（词法主路径，两调用点 read_token /
 *     parse_matched_pair 系）：查表前翻译 tokstr
 *     → L3 保留字（if/while/... 随机名）在词法识别处还原。
 *     【r16 教训】y.tab.c 里另有 find_reserved_word 函数，形态酷似主路径
 *     实为旁路死代码（无调用者）——patch 它则 L3 全程不生效（单脚本
 *     "假成功"：stderr 里 alias not found 才是真相）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* r21：复用路线 A 的 HMAC/流密码/tag（与 python 侧同源）。
 * 注意用的是 **crypto_isa.h**（保留 static 的独立副本），不是 crypto_core.h
 * —— 后者被 build_poc.sh 去掉了 5 处 static 以便 VMPacker 定位，若本文件
 * 也 include 它，v7core.o 与 isa_hook.o 会各导出一份同名全局符号，
 * ld.lld 报 duplicate symbol 链接失败（实测 5 条）。两份代码各自 local，
 * 互不撞车，且表解密链与载荷解密链互不干扰。 */
#include "crypto_isa.h"
#include "v7_isa_key.h"      /* r21：表加密主密钥（X^M 双串，rodata 无连续明文） */
#include "v7_isa_syms.h"     /* r20：第二层符号表（sym id → 真名，编进二进制） */

#define ISA_MAGIC      "V7IST"
#define ISA_VERSION    3      /* r21：v3 = 表体加密 + 掺假（v2 明文符号表已废弃） */
#define ISA_MAX_ENTRIES 128
#define ISA_MAX_NAME    64
#define ISA_SALT_LEN   16
#define ISA_TAG_LEN    16
#define ISA_HDR_LEN    (5 + 1 + ISA_SALT_LEN + 2)   /* magic+ver+salt+n = 24 */
#define ISA_MAX_FILE   (1L << 20)                   /* 表文件上限 1MB（防畸形分配） */

/* r27（ShellVMP T1）：L6 参数密文令牌。
 *
 * 与 L1-L5 的根本差异：L6 的真名是**业务字符串**（无限的、产物相关），
 * 无法预先编进 v7_isa_syms[]。因此 L6 **真名随表走**（表体已加密+MAC），
 * 不走第二层符号索引 —— sym 字段对 L6 无意义（置 0）。
 *
 * 安全边界：L1-L5 的「真名只在二进制里（受 VMP 保护）」性质，L6 **不具备**。
 * 换来的是「业务参数可无限扩展、无需重编 bash」。攻击者要拿 L6 真名，
 * 必须同时破表密钥（v7_isa_master，VMP 保护）+ 定位本文件的解密逻辑。 */
#define ISA_LAYER_PARAM  6      /* L6：参数密文令牌 */
#define ISA_MAX_ORIG     512    /* L6 真名上限（r33d.1：192→512B，中文
                                   3B/字，≈170 汉字；与 tools/v7_isa.py
                                   的 ISA_MAX_ORIG 必须同步改） */

typedef struct {
    int  layer;                 /* 1=builtin 2=external 3=keyword 4=param 5=path 6=参数令牌 */
    char alias[ISA_MAX_NAME];   /* payload 中出现的随机名 */
    unsigned short sym;         /* r20：第二层符号 id（真名不在表内） */
    /* r27：L6 专用 —— 真名**以密文态驻留**（关键安全设计）。
     *
     * 教训（r27 首版血案，实测抓到）：首版把真名解密后直接放进本结构体，
     * 结果 `isa_tab[]` 在 BSS 里长期驻留 {alias 明文, orig 明文} 相邻配对 ——
     * dump 一次就拿到完整对照表，整个方案等于没做。
     * 实测证据：rw-p(anon) 段里 `_7e88r5g\x00...\x00boot completed\x00`。
     *
     * 现行设计：orig_ct 存**真名的密文**（表体 CTR-XOR 流中对应的那一段），
     * v7_isa_param_decode 需要时才用 v7_keystream 按偏移单独解密到**栈上**，
     * 用完立即擦除。⇒ 内存中永远没有 {alias, orig} 的明文配对。
     */
    unsigned char orig_ct[ISA_MAX_ORIG];  /* L6：真名密文（非明文！） */
    unsigned int  orig_len;               /* L6：真名长度 */
    unsigned int  orig_off;               /* L6：真名在**整个密文段**中的绝对偏移
                                             （CTR 流位置，按需解密时定位 keystream） */
} isa_entry;

/* 表解密会话密钥（供 L6 按需解密；isa_load 成功后保留，进程生命周期）
 * 注意：它本身是"能解开 L6 真名的钥匙"，故受 VMP 保护，且不落盘。 */
static unsigned char isa_kenc[32];
static int isa_kenc_ok = 0;

/* 第二层解析：sym id → 真名（定义在 isa_tab/isa_n 声明之后）
 * 越界（掺假项/损坏表）返回 NULL → 该项不生效。 */

static isa_entry isa_tab[ISA_MAX_ENTRIES];
static int isa_n = 0;
static int isa_ready = 0;
static int isa_tried = 0;   /* 懒初始化哨兵：首次翻译时装载（r16 初版把 init
                               挂 v7_init → 被 V7_SELF 门控，裸 bash 永不装载） */

/* r20 第二层解析：sym id → 真名。
 * 越界（掺假项/损坏表）返回 NULL → 该项不生效。
 * 真名只存在于 v7_isa_syms[]（静态常量，编进二进制，受 VMP 保护），
 * 故 dump 内存或提取外部表都拿不到 alias→语义 的对照。 */
static const char *
isa_orig (int i)
{
    unsigned short s;

    if (i < 0 || i >= isa_n)
        return NULL;
    s = isa_tab[i].sym;
    if ((int) s >= V7_ISA_NSYMS)
        return NULL;
    return v7_isa_syms[s];
}

/* ---- r21：表解密（主密钥 → 会话密钥 → 内存解密）-----------------------
 *
 * 磁盘上只有密文：python 侧 serialize 输出的就是 ct，运行期释放到临时目录
 * 的也是 ct，本文件读入后**只在堆里解开**，用完立刻 memset + free ——
 * 任何时刻磁盘上没有明文表，也没有第二个明文副本。
 *
 * 攻击面收敛到一点：必须拿到 KM。而 KM 的重组发生在 v7_isa_master 里
 * （VMP 保护），rodata 中只有两串看起来毫无关系的随机 u32（X / M）。
 */

/* 主密钥重组：KM = X ^ M。两串各自都是随机数据，缺一不可。 */
V7_NOINLINE_ATTR static void
v7_isa_master (unsigned char km[32])
{
    unsigned int x[8];
    int i;

    for (i = 0; i < 8; i++)
        x[i] = v7_isa_km_x[i] ^ v7_isa_km_m[i];
    memcpy (km, x, 32);
    memset (x, 0, sizeof x);
}

/* salt → (kenc, kmac)。每份表 salt 不同 ⇒ 同一把 KM 下每产物表密钥也不同。 */
V7_NOINLINE_ATTR static void
v7_isa_derive (const unsigned char salt[ISA_SALT_LEN],
               unsigned char kenc[32], unsigned char kmac[32])
{
    unsigned char km[32];
    unsigned char lb[9 + ISA_SALT_LEN];

    v7_isa_master (km);
    memcpy (lb, "V7ISA-ENC", 9);
    memcpy (lb + 9, salt, ISA_SALT_LEN);
    hmac_sha256 (km, 32, lb, sizeof lb, kenc);
    memcpy (lb, "V7ISA-MAC", 9);
    hmac_sha256 (km, 32, lb, sizeof lb, kmac);
    memset (km, 0, sizeof km);
    memset (lb, 0, sizeof lb);
}

/* 与 tools/v7_isa.py serialize() 逐字节一致：
   "V7IST"(5B) + ver(1B=3) + salt(16B) + n(2B LE) + ct + tag(16B)
   明文段（加密前）= 每项{ layer(1B) + sym(2B LE) + alias_len(1B) + alias }
   ct = CTR-XOR(kenc, 明文段)；tag = HMAC(kmac, 文件除末 16B 外全部)[:16]

   失败一律返回 -1 并**清空表**：解密/MAC/解析任一环失败 = 整表作废，
   绝不留半张坏表继续跑（fail-closed）。调用方表现为 ISA 静默空转 ——
   产物退化为"未魔改 bash 语义"，不至于崩，但随机名不再被翻译。

   r28（T1.6）：解析改为**逐字段按需解密**（isa_dec_at → 栈上小缓冲），
   不再先造一份完整明文段。原因见 isa_dec_at 上方注释（堆明文残留）。 */
/* r28 关键修复（T1.6 排查所得）：
 *   r27 版 isa_load 先用 v7_crypt 把**整段表体**解密到一块 malloc 的 pt，
 *   再逐项解析、最后 memset+free。看似擦干净了 —— 实测**仍有明文残留**：
 *     [heap] 里抓到 'f1S04 counter positive\x06\x14\x00\x0ev7p_cbfno6b9m8T33...'
 *     即整张 L6 表（alias+orig 全配对）在堆上长期可读。
 *   根因：free(pt) 之后，那块 167B 的 chunk 回到分配器空闲链；首次后续
 *   malloc 复用同一地址时会把新数据写进去，**我们擦过的零被覆盖成调用方
 *   的数据**。实测反证：把 free(pt) 去掉（只擦不还）→ 泄漏消失。
 *   这不是"擦得不够狠"，而是**"先造一份完整明文"这个做法本身**给了窗口。
 *   修法（与 v7_isa_param_decode 同哲学）：**根本不产生整段明文**——
 *   只对每个字段按其密文偏移调用 v7_crypt 解密到栈上小缓冲，
 *   解析完立即擦除。堆上从此只有 raw（密文）。
 *   代价：每项多几次 v7_keystream 调用（表很小，可忽略）。 */
static void
isa_dec_at (const unsigned char *raw, size_t fsz, const unsigned char kenc[32],
            size_t off, unsigned char *out, size_t n)
{
    /* 单段 CTR-XOR：与 v7_crypt(raw + ISA_HDR_LEN, ...) 的对应位置逐字节一致。
     * off 是**明文段内**偏移；raw 中对应位置 = ISA_HDR_LEN + off。 */
    unsigned char ks[32];
    uint64_t blk;
    size_t start, done = 0;

    (void) fsz;
    blk = (uint64_t) (off / 32);
    start = off % 32;
    while (done < n)
      {
        size_t avail, chunk, t;
        v7_keystream (kenc, blk, ks);
        avail = 32 - start;
        chunk = (n - done < avail) ? (n - done) : avail;
        for (t = 0; t < chunk; t++)
          out[done + t] = (unsigned char)
              (raw[ISA_HDR_LEN + off + done + t] ^ ks[start + t]);
        done += chunk;
        blk++;
        start = 0;
      }
    memset (ks, 0, sizeof ks);
}

static int isa_load (const char *path)
{
    FILE *f;
    long fsz;
    unsigned char *raw = NULL;
    unsigned char kenc[32], kmac[32], tag[ISA_TAG_LEN];
    unsigned char fld[ISA_MAX_ORIG + ISA_MAX_NAME + 8];  /* 栈上字段暂存 */
    size_t plen = 0, pos = 0;
    int i, n, rc = -1;

    f = fopen (path, "rb");
    if (f == NULL)
        return -1;
    if (fseek (f, 0, SEEK_END) != 0)
        goto out;
    fsz = ftell (f);
    if (fsz < (long) (ISA_HDR_LEN + ISA_TAG_LEN) || fsz > ISA_MAX_FILE)
        goto out;
    rewind (f);
    raw = (unsigned char *) malloc ((size_t) fsz);
    if (raw == NULL)
        goto out;
    if (fread (raw, 1, (size_t) fsz, f) != (size_t) fsz)
        goto out;

    if (memcmp (raw, ISA_MAGIC, 5) != 0 || raw[5] != ISA_VERSION)
        goto out;
    n = raw[22] | (raw[23] << 8);
    if (n <= 0 || n > ISA_MAX_ENTRIES)
        goto out;

    /* Encrypt-then-MAC：先验 tag，再解密（避免对伪造密文做无用功） */
    v7_isa_derive (raw + 6, kenc, kmac);
    v7_tag (kmac, raw, (size_t) fsz - ISA_TAG_LEN, tag);
    if (!v7_ct_eq (tag, raw + fsz - ISA_TAG_LEN, ISA_TAG_LEN))
        goto out;

    plen = (size_t) fsz - ISA_HDR_LEN - ISA_TAG_LEN;

    /* r28：逐字段按需解密（**不再**整体解密到 pt）—— 见上方 isa_dec_at 说明 */
    pos = 0;
    for (i = 0; i < n; i++)
        {
          unsigned char layer, alen;

          if (pos + 1 > plen)
            goto bad;
          isa_dec_at (raw, fsz, kenc, pos, fld, 1);
          layer = fld[0];
          pos += 1;
          if (layer < 1 || layer > ISA_LAYER_PARAM)
            goto bad;
          isa_tab[i].layer = layer;
          isa_tab[i].orig_len = 0;

          if (layer == ISA_LAYER_PARAM)
            {
              /* r27 L6：layer + orig_len(2B LE) + alias_len(1B) + alias + orig
               *
               * 安全要点：真名**从 raw 拷密文**（orig 在流中的密文 = 明文 XOR
               * keystream，与 raw[ISA_HDR_LEN + pos + ...] 逐字节相同）。
               * 这样 isa_tab 里永久只有 {alias 明文, orig 密文}，
               * 攻击者 dump 不到配对。 */
              unsigned int olen;
              size_t ct_off;

              if (pos + 3 > plen)
                goto bad;
              isa_dec_at (raw, fsz, kenc, pos, fld, 3);
              olen = (unsigned int) (fld[0] | (fld[1] << 8));
              alen = fld[2];
              pos += 3;
              if (alen == 0 || alen >= ISA_MAX_NAME
                  || olen >= ISA_MAX_ORIG
                  || pos + (size_t) alen + olen > plen)
                goto bad;
              isa_dec_at (raw, fsz, kenc, pos, fld, alen);
              memcpy (isa_tab[i].alias, fld, alen);
              isa_tab[i].alias[alen] = '\0';
              pos += alen;
              /* orig 密文偏移（相对于密文段起点 ISA_HDR_LEN） */
              ct_off = pos;
              if (ct_off + olen > plen)
                goto bad;
              memcpy (isa_tab[i].orig_ct, raw + ISA_HDR_LEN + ct_off, olen);
              isa_tab[i].orig_len = olen;
              isa_tab[i].orig_off = (unsigned int) ct_off;
              pos += olen;
              isa_tab[i].sym = 0;
            }
          else
            {
              /* L1-L5：layer + sym(2B LE) + alias_len(1B) + alias */
              if (pos + 3 > plen)
                goto bad;
              isa_dec_at (raw, fsz, kenc, pos, fld, 3);
              isa_tab[i].sym = (unsigned short) (fld[0] | (fld[1] << 8));
              alen = fld[2];
              pos += 3;
              if (alen == 0 || alen >= ISA_MAX_NAME || pos + alen > plen)
                goto bad;
              isa_dec_at (raw, fsz, kenc, pos, fld, alen);
              memcpy (isa_tab[i].alias, fld, alen);
              isa_tab[i].alias[alen] = '\0';
              pos += alen;
            }
        }

    /* 保留会话密钥：L6 查表时按需解密（偏移 = 该 orig 在密文段中的位置） */
    memcpy (isa_kenc, kenc, 32);
    isa_kenc_ok = 1;

    rc = n;
    goto out;

bad:
    memset (isa_tab, 0, sizeof (isa_tab));   /* 半载状态不留用 */

out:
    /* raw 是密文，不是必须擦；但里面没有明文，擦不擦无安全含义。
     * 仍擦除是防"密文段被误当明文引用"，成本可忽略。 */
    if (raw)
        {
          memset (raw, 0, (size_t) fsz);
          free (raw);
        }
    memset (fld, 0, sizeof fld);
    memset (kenc, 0, sizeof kenc);
    memset (kmac, 0, sizeof kmac);
    memset (tag, 0, sizeof tag);
    if (f)
        fclose (f);
    return rc;
}

/* 启动期装载（v7_isa_init 可被显式调用；两个翻译函数入口还会懒触发）。
 * 失败静默空转：无表时产物必须与未魔改 bash 行为一致。 */
void v7_isa_init (void)
{
    const char *p;

    if (isa_tried)
        return;
    isa_tried = 1;
    isa_n = 0;
    isa_ready = 0;
    p = getenv ("V7_ISA_TABLE");
    if (p == NULL || *p == '\0')
        return;
    isa_n = isa_load (p);
    /* r21-1：失败统一归零，**绝不让 isa_n 取负值**。
     * 实测（aarch64 + VMP + qemu）：表存在但损坏/为空时 isa_load 返回 -1，
     * 后续 VMP 化的翻译函数拿到负 isa_n 直接 SIGSEGV（rc=139，脚本毫无输出）。
     * 无 VMP 版不崩（负值与 0 都只是"循环不执行"），可见是 VMP 对负计数
     * 的处理差异。归零后语义不变（空表 = 不翻译），但彻底避开这个雷区。 */
    if (isa_n < 0)
        isa_n = 0;
    if (isa_n > 0)
        isa_ready = 1;
}

/* L1/L2 命令词翻译（execute_simple_command 插桩点）。
 * 命中 → *pname 替换为 orig（新分配）；未命中 → 原样。 */
void v7_isa_translate_cmd (char **pname)
{
    int i;

    if (isa_tried == 0)
        v7_isa_init ();          /* 懒装载：不依赖 V7_SELF/v7_init 流程 */
    if (isa_ready == 0 || pname == NULL || *pname == NULL)
        return;
    for (i = 0; i < isa_n; i++)
        {
          if ((isa_tab[i].layer == 1 || isa_tab[i].layer == 2) &&
              strcmp (*pname, isa_tab[i].alias) == 0)
            {
              const char *o = isa_orig (i);      /* r20：走第二层 */
              char *d = o ? strdup (o) : NULL;
              if (d != NULL)
                *pname = d;   /* 原词不 free：WORD_DESC 归 unwind 栈管理 */
              return;
            }
        }
}

/* r16-5 L4 位置参数：变量别名 → 真实位置参数名（"1".."9"，即 bash 里
   存放位置参数的 ordinary 变量名）。命中返回 strdup 堆拷贝（沿用
   translate_kw 的堆契约）；未命中 / 无表 / 分配失败返回 NULL（调用方按
   "不翻译"处理，原名照跑 100% 兼容）。
   运行时才取值 ⇒ shift 后的漂移天然跟随，无需构建期绑定，也无需降级检测。 */
char *
v7_isa_translate_var (const char *name)
{
    int i;

    if (isa_tried == 0)
        v7_isa_init ();
    if (isa_ready == 0 || name == NULL || *name == '\0')
        return NULL;
    for (i = 0; i < isa_n; i++)
        {
          if (isa_tab[i].layer == 4 && strcmp (name, isa_tab[i].alias) == 0)
            {
              const char *o = isa_orig (i);   /* r20：走第二层 */
              return o ? strdup (o + 1) : NULL;   /* 表项真名形如 "$1" */
            }
        }
    return NULL;
}

/* r16-5 L4 路径常量：词内子串还原（随机 token → 原路径）。
   命中返回新分配串（调用方换取指针，勿 free 旧指针——WORD_DESC 归 unwind
   栈管理）；无命中返回 NULL。首命中才 malloc，避免热路径每词都分配。

   r17-1（A5 血案）——**词边界锚定**：
   旧实现用裸 strstr 在整个词里找别名。别名当时只有 4 个 hex 字符，
   于是**任何数据**（sha512 摘要 / base64 / 用户文本）里偶然出现的
   同形子串都会被误改写：实测 "/data"→"f054"，sh512 摘要第 7 轮
   出现 "f054" 即被改成 "/data"，令 kdf 密钥链分叉、产物静默崩。
   修法：只在**词首**匹配，且要求别名整体构成一个合法 token ——
   右侧下一字符不得是 [A-Za-z0-9_]（否则是更长标识符的前缀，非别名）。
   别名自身已带 "v7p_" 前缀 + 10 位随机段（见 v7_isa.py），
   两道防线叠加后，随机数据撞车概率可忽略。 */
/* r32：v7_isa_translate_paths 的单步替换。
 * 【为什么是外部链接】同 v7_isa_param_crypt —— static+noinline 在 clang -O2
 * 下会被内联回调用者，函数体膨胀到 388 字节，而 VMPacker 对 >200 字节的
 * 函数翻译会出错（实测 388/392 两个全崩，≤188 的全正常）。拆出去后主函数
 * 只剩"循环 + 判断 + 指针推进"。
 *
 * 返回值：1 = 已替换（*out_new 为新串，调用方接管）
 *         0 = 本条规则未命中（继续下一条）
 *        -1 = 致命（真名为空 / malloc 失败），调用方 break（保持原语义） */
int
v7_isa_path_step (const char *cur, int i, char **out_new)
{
    size_t alen, olen, wlen;
    const char *o;
    char *tmp, nxt;

    if (isa_tab[i].layer != 5)
      return 0;
    alen = strlen (isa_tab[i].alias);
    /* 词首锚定：必须从 cur 的第 0 个字符开始 */
    if (strncmp (cur, isa_tab[i].alias, alen) != 0)
      return 0;
    /* 右边界：别名后的下一字符不得是标识符字符（防前缀误配） */
    nxt = cur[alen];
    if (nxt == '_'
        || (nxt >= 'a' && nxt <= 'z')
        || (nxt >= 'A' && nxt <= 'Z')
        || (nxt >= '0' && nxt <= '9'))
      return 0;
    o = isa_orig (i);                                  /* r20：走第二层 */
    if (o == NULL || (olen = strlen (o)) == 0)
      return -1;
    wlen = strlen (cur);
    tmp = malloc (wlen + olen + 64);
    if (tmp == NULL)
      return -1;
    memcpy (tmp, o, olen);
    strcpy (tmp + olen, cur + alen);
    *out_new = tmp;
    return 1;
}

char *
v7_isa_translate_paths (const char *word)
{
    int i;
    char *cur, *out = NULL;

    if (isa_tried == 0)
        v7_isa_init ();
    if (isa_ready == 0 || word == NULL || *word == '\0')
        return NULL;
    cur = (char *) word;
    for (i = 0; i < isa_n; i++)
      {
        char *tmp = NULL;
        int r = v7_isa_path_step (cur, i, &tmp);

        if (r < 0)
          break;                 /* 真名为空 / 分配失败：保持原有 break 语义 */
        if (r == 0)
          continue;
        if (out != NULL)
          free (out);            /* 上一轮结果已拷进 tmp，可安全释放 */
        out = tmp;
        cur = out;               /* 后续 token 在新串上继续找 */
      }
    return out;
}

/* L3 保留字翻译（y.tab.c CHECK_FOR_RESERVED_WORD 宏插桩点，见 isa_hook.py）。
 * 命中 → 返回 orig；未命中 → 原样返回 tokstr。**不分配，不交出所有权**。
 *
 * 【所有权契约（r16-5 血案，两次迭代才踩到底）】
 * 调用方的 tok 是 read_token_word 的 buffer 指针 —— 更精确地说，`token`
 * 是**文件作用域 static**，且 parse_matched_pair 会递归回词法器。
 *   v1 返回 static 表指针          → 调用方 FREE(token) 释放非堆地址，堆损坏；
 *   v2 返回 strdup 堆拷贝          → 解了 double/dangling free，但把 static
 *                                    token 改成了一个 malloc 的小块；外层
 *                                    RESIZE_MALLOCED_BUFFER(token,..) 随即
 *                                    xrealloc 它 → munmap_chunk(): invalid
 *                                    pointer（且只在「递归词法 + 递归内命中
 *                                    别名」的组合下炸，单句探针全绿）；
 *   v3（现行）只返回视图，绝不改 tok 指向：由宏负责
 *                                    RESIZE + strcpy + 同步 token_index。
 * ⇒ 教训：在 C 里 hook「替换字符串」时，先问清这个指针归谁、后续会不会被
 *   realloc/free。换内容是安全的，换 owner 是把炸弹埋到下游几十行之外。
 * ⇒ 本函数只保证返回合法 NUL 结尾串；长度同步与扩容归调用方（宏）契约。
 */
const char *
v7_isa_translate_kw (const char *tokstr)
{
    int i;

    if (isa_tried == 0)
        v7_isa_init ();          /* 懒装载：与命令词路径保持一致 */
    if (isa_ready == 0 || tokstr == NULL)
        return tokstr;
#ifdef V7_ISA_DEBUG
    fprintf (stderr, "[ISA-KW] %s\n", tokstr);
#endif
    for (i = 0; i < isa_n; i++)
        {
          if (isa_tab[i].layer == 3 && strcmp (tokstr, isa_tab[i].alias) == 0)
            {
              const char *o = isa_orig (i);        /* r20：走第二层 */
              return o ? (char *) o : tokstr;      /* 视图，见上方「所有权契约」 */
            }
        }
    return tokstr;
}

/* ---- r27（ShellVMP T1）：L6 参数密文令牌查询 ---------------------------
 *
 * 供自定义 builtin（v7_builtin_takeover.c）调用：把参数位上的密文令牌
 * 还原为业务真名，再由 builtin 自己输出（bash 全程不接触明文）。
 *
 * 契约（关键，与 translate_paths 不同）：
 *   - **整段匹配**（strcmp 全等），不是子串替换。
 *     理由（r24 实测）：参数令牌占据整个词，任何部分匹配都会误伤。
 *   - 解密结果写入调用方提供的 **out** 缓冲（栈上），调用方用完负责擦除。
 *     本函数**不返回指向内部状态的指针** —— 表里只存密文，永不解密驻留。
 *   - 未命中 / 无表 / 缓冲不足 → 返回 0（调用方按"原样输出"处理）。
 *
 * 【r27 安全设计要点】
 *   表内 L6 真名以**密文态**常驻（isa_tab[i].orig_ct）。本函数按 CTR-XOR
 *   的随机可访问性，用 v7_keystream 单独生成该偏移处的密钥流，就地解密
 *   到 out，随即擦除密钥流缓冲。⇒ 内存中任何时刻都**没有** {alias, orig}
 *   的明文配对（首版正是因为把明文放进结构体而在内存里露馅，实测抓到）。
 */
/* r32：v7_isa_param_decode 的解密循环（noinline，不进 VMP 保护面）。
 * 独立出来的原因见调用点注释：VMPacker 对"局部数组取地址 + 嵌套循环"
 * 的翻译存在语义错误，把这类循环留在被保护函数里会静默出错。
 * 本函数不出现在 build_poc.sh 的 -func 列表 ⇒ 不参与 VM 化。 */
/* r32：v7_isa_param_decode 的解密循环。
 *
 * 【为什么不是 static】必须是**外部链接**：
 *   1) static + noinline 在 clang -O2 下仍会被内联回调用者（实测：helper
 *      符号直接消失，XOR 循环展开进 v7_isa_param_decode，392 字节）；
 *   2) VMPacker 对**函数体大小敏感** —— 实测 ≤188 字节的翻译函数全部正常，
 *      388/392 字节的两个全部出错（见 R22_CHANGES.md §15.4 的大小对照表）。
 *      把循环挪到独立的外部函数后，被保护的 v7_isa_param_decode 只剩
 *      "查表 + BL + 写终止符"，约 30 条指令，稳稳落在安全区间内。
 *   3) 外部函数不进 -func 列表 ⇒ 不参与 VM 化，语义天然正确。
 */
void
v7_isa_param_crypt (const unsigned char *ct, size_t abs_off, unsigned int olen,
                    char *out)
{
    unsigned char ks[32];
    uint64_t blk = (uint64_t) (abs_off / 32);
    size_t start = abs_off % 32;
    size_t done = 0;

    while (done < olen)
      {
        size_t avail, chunk, t;

        v7_keystream (isa_kenc, blk, ks);
        avail = 32 - start;
        chunk = ((size_t) olen - done < avail) ? ((size_t) olen - done) : avail;
        for (t = 0; t < chunk; t++)
          out[done + t] = (char) (ct[done + t] ^ ks[start + t]);
        done += chunk;
        blk++;
        start = 0;
      }
    out[olen] = '\0';
    memset (ks, 0, sizeof ks);
}

/* r32：L6 令牌查表。外部链接、不进保护面（同 v7_isa_param_crypt 的理由）。
 * 返回命中表项下标；未命中 / 表未就绪 / 参数非法 → -1。 */
int
v7_isa_param_lookup (const char *tok)
{
    int i;

    if (isa_tried == 0)
        v7_isa_init ();
    if (isa_ready == 0 || isa_kenc_ok == 0 || tok == NULL || *tok == '\0')
      return -1;
    for (i = 0; i < isa_n; i++)
      {
        if (isa_tab[i].layer != ISA_LAYER_PARAM)
          continue;
        if (strcmp (tok, isa_tab[i].alias) == 0)
          return i;
      }
    return -1;
}

int
v7_isa_param_decode (const char *tok, char *out, size_t outsz)
{
    int i;
    unsigned int olen;

    if (out == NULL || outsz == 0)
      return 0;
    /* r32：查表与解密都在外部函数里（不参与 VM 化），本函数只留调度。
     * 实测 VMPacker 对大函数体翻译会出错：392B 时输出多 1 字节，
     * 240B 仍不行，压到 ~60B 后才稳（见 R22_CHANGES.md §15.4）。 */
    i = v7_isa_param_lookup (tok);
    if (i < 0)
      return 0;
    olen = isa_tab[i].orig_len;
    if (olen == 0 || (size_t) olen + 1 > outsz)
      return 0;
    v7_isa_param_crypt (isa_tab[i].orig_ct, (size_t) isa_tab[i].orig_off,
                        olen, out);
    out[olen] = '\0';
    return (int) olen;
}

/* r33e：L6 混合串子串扫描 —— 整词 decode miss 后的兜底路径。
 *
 * 背景（r33e）：decode 只做整词精确匹配，"静态令牌+动态值"在词展开阶段
 * 融合成新词（"v7p_xxx"$? → v7p_xxx0），整词查表必然 miss，令牌原样
 * 漏出（r33 实验 2/3）。本函数对 miss 词做**子串扫描**：寻找 14 字符
 * 令牌形态（"v7p_" + 10 位 [a-z0-9_]），逐个查表，命中则原位替换真名。
 *
 * 安全性三重保险：
 *   1. 形态校验：候选严格 = "v7p_" + 10 位 [a-z0-9_]，正常文本（尤其
 *      中文 UTF-8）几乎不可能命中该形态；
 *   2. 查表精确匹配：形态对但表内无此 alias → 原样保留；
 *   3. 容量 fail-safe：任一时刻写不下 → 整条放弃返回 0，调用方按未
 *      命中处理（令牌原样输出，绝不产生半解密混合体）。
 *
 * VMP 边界（r32 教训）：本函数**不进** -func 保护面（外部链接、重活
 * 函数体）；v7_isa_param_decode 本体一字未动 —— 整词路径行为零变化，
 * 老表/老产物完全不受影响，子串扫描纯属新增兜底分支。
 *
 * 词法实验背书（r33 实验 4）：decode 发生在词展开之后（echo builtin
 * 执行时），所以扫描看到的就是展开后的最终词，$? 等动态值已是结果
 * 文本 —— 子串扫描时机天然正确，无需涉及任何 shell 求值语义。
 *
 * 返回：发生替换时输出长度；未命中/表未就绪/放不下 → 0。
 */
static int
v7_tok_alpha (char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

int
v7_isa_param_scan (const char *word, char *out, size_t outsz)
{
    size_t i, o;
    int hit = 0;

    if (word == NULL || out == NULL || outsz < 32)
        return 0;
    if (isa_tried == 0)
        v7_isa_init ();
    if (isa_ready == 0 || isa_kenc_ok == 0)
        return 0;

    i = 0;
    o = 0;
    while (word[i] != '\0')
      {
        if (word[i] == 'v' && strncmp (word + i, "v7p_", 4) == 0)
          {
            char cand[16];
            size_t j;
            int full = 1;

            for (j = 0; j < 10; j++)
              {
                char c = word[i + 4 + j];

                if (c == '\0' || !v7_tok_alpha (c))
                  {
                    full = 0;
                    break;
                  }
                cand[4 + j] = c;
              }
            if (full)
              {
                int idx;

                memcpy (cand, "v7p_", 4);
                cand[14] = '\0';
                idx = v7_isa_param_lookup (cand);
                if (idx >= 0)
                  {
                    unsigned int olen = isa_tab[idx].orig_len;

                    if (olen == 0 || o + olen + 1 > outsz)
                        return 0;       /* fail-safe：整条放弃 */
                    v7_isa_param_crypt (isa_tab[idx].orig_ct,
                                        (size_t) isa_tab[idx].orig_off,
                                        olen, out + o);
                    o += olen;
                    i += 14;
                    hit = 1;
                    continue;
                  }
              }
          }
        /* 普通字符（含 UTF-8 多字节序列）：逐字节原样复制。
         * miss 窗口只推进 1 字符再继续找 —— 相邻/嵌套令牌不错漏。 */
        if (o + 1 >= outsz)
            return 0;                   /* fail-safe：整条放弃 */
        out[o++] = word[i++];
      }
    if (!hit)
        return 0;
    out[o] = '\0';
    return (int) o;
}

/* 供 builtin 判断"是否需要接管"：产物带了 L6 表才启用自定义 echo，
 * 否则保持原生行为（无表 = 完全等价于未魔改 bash，fail-closed）。 */
int
v7_isa_has_param_table (void)
{
    int i;

    if (isa_tried == 0)
        v7_isa_init ();
    if (isa_ready == 0)
        return 0;
    for (i = 0; i < isa_n; i++)
        if (isa_tab[i].layer == ISA_LAYER_PARAM)
            return 1;
    return 0;
}
