/* v7_shf_inject_mksh.c —— V7 骨架注入层（mksh 版，C2）
 *
 * 对应 bash 线的 zread.c.v7poc。**实现策略不同**，这是有意的设计选择。
 *
 * ── 两条线的差异：读层劫持 vs 打开层劫持 ────────────────────────────────
 *
 *   bash（zread.c.v7poc）：劫持**读取层**。
 *     解释器读到的是密文，zread 边读边解密（v7_read → v7c_stream_xor），
 *     明文"逐块过境、即写即抹"。密文从 /proc/self/exe 尾部读出。
 *
 *   mksh（本文件）：劫持**打开层**（shf_open 入口）。
 *     在"要打开一个文件"这一步判断：若 name 指向受保护脚本，就现场把
 *     密文解密进一个 **memfd**（匿名内存文件），让 shf 从这个 memfd 读。
 *     之后 lex/parse 全程拿到的就是普通文件流 —— **读取语义完全不动**。
 *
 * ── 为什么打开层更好（mksh 特有的机会） ────────────────────────────────
 *   1) `shf_open()` 是 mksh **统一的脚本打开点**，全树仅 5 个调用者，
 *      其中只有 2 个是脚本入口（main.c:532 主脚本 / main.c:758 include）。
 *      改一处即覆盖全部脚本来源。
 *   2) 只改"打开"这一步，读取语义零改动 ⇒ **顺带绕开 pipe 短读问题**
 *      （bash 线 elf 形态里 mksh 把 8192 字节短读当 EOF 的那个阻塞项）。
 *      mksh 从一个**完整、可 seek 的 memfd** 读，短读语义问题不复存在。
 *   3) shf 层抽象完好，替换 fd 后所有下游（lex/parse）无感。
 *
 * ── 安全边界（诚实记录） ────────────────────────────────────────────────
 *   · memfd 是**匿名内存文件**（memfd_create）：不出现在磁盘、无路径、
 *     进程退出即释放。但它**可被同 uid 进程通过 /proc/PID/fd/N 读到** ——
 *     这是与 bash 线"明文只在 4KB lbuf 驻留"相比的**保护面折损**。
 *     缓解：脚本执行完立即关闭 fd；可加 F_SEAL_* 封印（见下）。
 *   · 明文在一次 malloc 里完整存在（bash 线是逐块），属同一折损。
 *     理由：mksh 的 shf 需要可 seek 的文件，流式注入要改 shf 层本身
 *     （改动面大得多，且失去"读取语义不动"这个最大优势）。
 *   · 折损是**有意接受的权衡**：换来的是"实现干净 + 绕开 pipe 短读"。
 *     如果要找回逐块过境，走 bash 线的读层方案（但那是 bash 专属）。
 *
 * ── fail-closed 原则 ────────────────────────────────────────────────────
 *   无 V7_SELF / 无内嵌 blob / 非目标路径 → 返回原 fd 语义（返回 -1 表示
 *   "别接管，走原生 binopen3"）。裸 mksh 跑普通脚本行为零变化。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "sh.h"

/* crypto_isa.h 提供的 V7 密码学（与 isa_hook.c 共用同一份；保留 static，
 * 不参与 VMP 去 static 流程，避免重复符号）。 */
#include "crypto_isa.h"

/* =========================================================================
 * blob v3 布局（与 bash 线 zread.c.v7poc / v7_embed.py **逐字节一致**）：
 *   [ct][tag 16][salt 16][N 4 LE][wb_table 256][wb_perm 256][wb_mask 256][flags 4][len 4]
 *   len = ctlen + 812
 * 口令模式与离线模式共用布局（口令模式下白盒三表填随机诱饵）。
 * ========================================================================= */
#define V7_BLOB_OVERHEAD 812
#define V7_WB_SIZE       256
#define V7_FLAG_PASSMODE 1u
#define V7_FREEZE_LIMIT_S 30

/* 诊断（编译期开关，与 bash 线同哲学：生产构建整体剔除） */
#if defined(V7_DIAG)
#  define V7_LOG(...) do { if (v7_diag_on()) fprintf(stderr, __VA_ARGS__); } while (0)
static int v7_diag_on(void)
{
    const char *p = getenv("V7_DIAG");
    return (p != NULL && *p != '\0' && !(p[0] == '0' && p[1] == '\0'));
}
#else
#  define V7_LOG(...) do { } while (0)
#endif

static size_t
v7_le32(const unsigned char *p)
{
    return (size_t) p[0] | ((size_t) p[1] << 8)
         | ((size_t) p[2] << 16) | ((size_t) p[3] << 24);
}

/* ---- 状态 ------------------------------------------------------------- */
static int v7_tried = 0;
static int v7_ready = 0;             /* 1 = blob 已成功解密 */
static unsigned char *v7_plain = NULL;
static size_t v7_plain_len = 0;
static long long v7_last_mono = -1;

/* ---- 反调试：环境守卫（与 bash 线 r15 同款，触发即拒绝） ---------------- */
static void
v7_die(int code, const char *msg)
{
    fprintf(stderr, "v7: %s\n", msg);
    exit(code);
}

static unsigned long long
v7_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (unsigned long long) ts.tv_sec * 1000ULL
         + (unsigned long long) (ts.tv_nsec / 1000000L);
}

/* TracerPid 自检：非 0 说明被 ptrace 附着 ⇒ 拒绝（rc=113） */
static void
v7_tracerpid_check(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];

    if (f == NULL)
        return;
    while (fgets(line, sizeof line, f) != NULL)
        if (strncmp(line, "TracerPid:", 10) == 0)
          {
            int pid = atoi(line + 10);

            if (pid != 0)
              {
                fclose(f);
                v7_die(113, "检测到调试器（TracerPid != 0）");
              }
            break;
          }
    fclose(f);
}

static void
v7_env_guards(void)
{
    const char *p;

    /* LD_PRELOAD：可劫持我们的解密过程 */
    p = getenv("LD_PRELOAD");
    if (p != NULL && *p != '\0')
        v7_die(113, "环境异常（LD_PRELOAD）");
    /* xtrace 类：产物会把自己的解密过程回显出来 */
    if (getenv("BASH_XTRACEFD") != NULL)
        v7_die(113, "环境异常（BASH_XTRACEFD）");
    p = getenv("PS4");
    if (p != NULL && strstr(p, "v7") != NULL)
        v7_die(113, "环境异常（PS4）");
}

static void
v7_freeze_check(void)
{
    long long now;

    /* 进程被 SIGSTOP/调试器冻结后再醒来，单调时钟差值会异常大 */
    if (v7_last_mono < 0)
      {
        v7_last_mono = (long long) v7_now_ms();
        return;
      }
    now = (long long) v7_now_ms();
    if (now - v7_last_mono > (long long) V7_FREEZE_LIMIT_S * 1000LL)
        v7_die(113, "疑似调试冻结（单调时钟异常停顿）");
    v7_last_mono = now;
}

/* ---- 解密 ------------------------------------------------------------- */
/* 从自身 ELF 尾部读出内嵌 blob 并解密到 v7_plain。
 * 返回 1 成功 / 0 未激活或失败（fail-closed：调用方走原生路径）。 */
static int
v7_init(void)
{
    const char *pass;
    unsigned char seed[32], kenc[32], kmac[32], tag_calc[16], lenbuf[4];
    const unsigned char *p_tag, *p_salt, *p_N, *p_wbt, *p_wbp, *p_wbm, *p_flags;
    v7_stream_ctx str;
    int fd;
    struct stat st;
    off_t total, blob_start;
    size_t taillen, ctlen, got, N, off;
    unsigned int flags;
    ssize_t n;
    unsigned char *tail;

    v7_tried = 1;

    /* 仅 V7_SELF 存在时激活；否则完全走上游逻辑 */
    if (getenv("V7_SELF") == NULL)
      {
        V7_LOG("V7DIAG: 未检测到 V7_SELF —— 骨架注入未激活\n");
        return 0;
      }
    V7_LOG("V7DIAG: 骨架注入激活（V7_SELF 已设置）\n");

    v7_env_guards();

    fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0)
      {
        V7_LOG("V7DIAG: 无法打开 /proc/self/exe\n");
        return 0;                    /* 非 ELF 形态（普通 mksh）→ 不接管 */
      }
    if (fstat(fd, &st) != 0 || st.st_size < (off_t) (V7_BLOB_OVERHEAD + 4))
      {
        close(fd);
        V7_LOG("V7DIAG: 产物未内嵌脚本（尺寸异常）\n");
        return 0;
      }
    total = st.st_size;
    if (pread(fd, lenbuf, 4, total - 4) != 4)
      {
        close(fd);
        V7_LOG("V7DIAG: 读取尾部长度失败\n");
        return 0;
      }
    taillen = v7_le32(lenbuf);
    if (taillen < (size_t) V7_BLOB_OVERHEAD + 1 || (off_t) taillen + 4 > total)
      {
        close(fd);
        V7_LOG("V7DIAG: 产物未内嵌脚本（尾部布局无效）\n");
        return 0;
      }
    ctlen = taillen - (size_t) V7_BLOB_OVERHEAD;
    blob_start = total - (off_t) taillen;
    V7_LOG("V7DIAG: 定位尾部 blob —— 产物 %lld 字节，密文 %zu 字节\n",
           (long long) total, ctlen);

    tail = (unsigned char *) malloc(taillen);
    if (tail == NULL)
      {
        close(fd);
        return 0;
      }
    got = 0;
    while (got < taillen)
      {
        n = pread(fd, tail + got, taillen - got, blob_start + (off_t) got);
        if (n <= 0)
            break;
        got += (size_t) n;
      }
    close(fd);
    if (got != taillen)
      {
        free(tail);
        return 0;
      }

    p_tag   = tail + ctlen;
    p_salt  = tail + ctlen + 16;
    p_N     = tail + ctlen + 32;
    p_wbt   = tail + ctlen + 36;
    p_wbp   = tail + ctlen + 292;
    p_wbm   = tail + ctlen + 548;
    p_flags = tail + ctlen + 804;
    N = v7_le32(p_N);
    flags = (unsigned int) v7_le32(p_flags);

    if (flags & V7_FLAG_PASSMODE)
      {
        pass = getenv("V7_PASS");
        if (pass == NULL || *pass == '\0')
          {
            free(tail);
            v7_die(114, "缺少 V7_PASS（产物需要外层口令）");
          }
        V7_LOG("V7DIAG: 口令模式 scrypt（N=%u）——慢是正常的\n", (unsigned) N);
        if (v7c_scrypt_kdf((const unsigned char *) pass,
                           (unsigned int) strlen(pass),
                           p_salt, 16, seed, 32, (unsigned int) N) != 0)
          {
            free(tail);
            v7_die(114, "KDF 失败（内存不足？）");
          }
      }
    else
      {
        /* 离线分发：白盒三表解码 seed（无需口令） */
        v7c_wb_decode(p_wbt, p_wbp, p_wbm, seed);
        V7_LOG("V7DIAG: 白盒三表解码完成（离线模式）\n");
      }

    v7c_keys(seed, kenc, kmac);
    v7c_tag(kmac, tail, (unsigned int) ctlen, tag_calc);
    if (v7c_ct_eq(tag_calc, p_tag, 16) != 1)
      {
        memset(seed, 0, 32); memset(kenc, 0, 32); memset(kmac, 0, 32);
        free(tail);
        V7_LOG("V7DIAG: HMAC 认证失败（口令错误 或 产物被篡改）\n");
        v7_die(114, "认证失败（口令错误或产物被篡改）");
      }
    V7_LOG("V7DIAG: 骨架验签通过（密文 %zu 字节）\n", ctlen);

    /* 解密到一块内存（C2 的折损点，见文件头"安全边界"） */
    v7_plain = (unsigned char *) malloc(ctlen + 1);
    if (v7_plain == NULL)
      {
        free(tail);
        return 0;
      }
    v7c_stream_init(&str, kenc);
    off = 0;
    while (off < ctlen)
      {
        unsigned int chunk = (ctlen - off > 65536) ? 65536 : (unsigned int) (ctlen - off);

        v7c_stream_xor(&str, tail + off, v7_plain + off, chunk);
        off += chunk;
      }
    v7c_stream_wipe(&str);
    v7_plain[ctlen] = '\0';
    v7_plain_len = ctlen;
    free(tail);

    memset(seed, 0, 32); memset(kenc, 0, 32); memset(kmac, 0, 32);

    v7_tracerpid_check();
    v7_freeze_check();
    v7_ready = 1;
    V7_LOG("V7DIAG: 解密完成 —— 骨架就绪（%zu 字节明文）\n", v7_plain_len);
    return 1;
}

/* ---- 对外入口：给 shf.c 调用 ------------------------------------------ */
/*
 * v7_shf_inject —— 判断 name 是否是"受保护的主脚本"，是则返回一个
 * 指向**解密后明文**的 fd（memfd），否则返回 -1（调用方走原生 binopen3）。
 *
 * 判定规则（严格，避免误接管）：
 *   1) V7_SELF 存在（否则完全不动）
 *   2) 自身 ELF 里有合法 blob
 *   3) name 指向的就是**我们自己**（argv[0]/脚本参数进程）—— 
 *      具体做法：本函数只在**首次**被调用且 name 非空时接管一次。
 *
 * 为什么用"首次调用"而不是路径比对：
 *   mksh 主脚本路径与 /proc/self/exe 未必同名（可能是软链、可能是
 *   `mksh script.sh` 形态）。bash 线靠"读的是 /proc/self/exe"天然规避这个
 *   问题（它根本不看 name）。C2 的形态下，第一次 shf_open 就是主脚本 ——
 *   这是 mksh 启动序的既定事实（main.c:532 早于 include/重定向/历史）。
 *   用一次性标志位比路径猜谜可靠得多，也避免误接管 `source` 的普通文件。
 */
int
v7_shf_inject(const char *name)
{
    int mfd;
    ssize_t w;

    if (name == NULL || *name == '\0')
        return -1;                   /* stdin / 空名 → 不接管 */

    if (!v7_tried)
      {
        if (!v7_init())
            return -1;               /* 未激活 / 无 blob → fail-closed */
      }
    if (!v7_ready || v7_plain == NULL)
        return -1;

    /* 一次性：接管后置位，后续 shf_open（include/重定向/历史）不再接管 */
    v7_ready = 0;

    V7_LOG("V7DIAG: 接管脚本打开 \"%s\" → 注入 %zu 字节明文\n",
           name, v7_plain_len);

    /* memfd_create：匿名内存文件（不出现在磁盘、无路径）。
     * 内核 >= 3.17。老内核回落到 O_TMPFILE 不可用时直接失败
     * （fail-closed 会让脚本以"文件不存在"报错，比静默错更可诊断）。 */
#ifdef __NR_memfd_create
    mfd = (int) syscall(__NR_memfd_create, "v7skel", 0);
#else
    mfd = -1;
#endif
    if (mfd < 0)
      {
        /* 回落：unlink 后即刻打开的 tmpfile 语义（尽力而为） */
        char tmpl[] = "/tmp/.v7skelXXXXXX";

        mfd = mkstemp(tmpl);
        if (mfd >= 0)
            unlink(tmpl);
      }
    if (mfd < 0)
      {
        V7_LOG("V7DIAG: 无法创建注入用内存文件\n");
        return -1;
      }

    w = 0;
    while ((size_t) w < v7_plain_len)
      {
        ssize_t n = write(mfd, v7_plain + w, v7_plain_len - (size_t) w);

        if (n <= 0)
          {
            close(mfd);
            V7_LOG("V7DIAG: 写入注入文件失败\n");
            return -1;
          }
        w += n;
      }
    if (lseek(mfd, 0, SEEK_SET) != 0)
      {
        close(mfd);
        return -1;
      }

    /* 明文已交给 fd —— 立即擦除内存副本（缩短窗口）。
     * 注意：memfd 里仍是明文，攻击者可通过 /proc/PID/fd/N 读到，
     * 这是 C2 的既有折损，见文件头说明。 */
    memset(v7_plain, 0, v7_plain_len);
    free(v7_plain);
    v7_plain = NULL;

    return mfd;
}
