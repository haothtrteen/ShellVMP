/* v7_wipe.h —— r22 明文擦除与抗 dump 支持
 *
 * 设计目标（三层纵深的第一、二层）：
 *   第一层（断读）：PR_SET_DUMPABLE=0 / MADV_DONTDUMP / mlock
 *   第二层（擦除）：explicit_bzero 擦明文字节 + MADV_DONTNEED 还页
 *
 * 为什么需要：
 *   unset _va 只解绑变量名，堆块内容一个字节没变（实测：_I 密文在内存
 *   有 5 份副本、骨架明文有 8 份递减前缀副本）。攻击者扫 /proc/pid/mem
 *   即可捞到全部明文。本文件提供：
 *     1. v7_wipe_mem()      —— 可靠擦除（防编译器优化掉 memset）
 *     2. v7_wipe_region()   —— 整页还内核（MADV_DONTNEED）
 *     3. v7_argv_wipe()     —— 擦除 argv 传参链（execve 后残留的明文脚本参数）
 *     4. v7_harden_memory() —— 第一层断读调用集合
 *
 * 边界（诚实记录）：
 *   - 纯擦除挡不住多线程高频轮询（窗口 1-10ms 仍可能被撞上）
 *   - 断读层（v7_harden_memory）是对付高频轮询的唯一解
 *   - root + 内核模块下前两层均可绕，第三层（伪块/掺假）是最后的成本墙
 */
#ifndef V7_WIPE_H
#define V7_WIPE_H

#include <stddef.h>
#include <string.h>

/* ---- 可靠擦除：不依赖 memset 是否被优化掉 ----
 * 用 volatile 指针逐字节写，编译器无法证明写入无效。
 * gcc/clang 有 __builtin_explicit_bzero 时优先用（内建不会被优化）。 */
static void v7_wipe_mem(void *p, size_t n)
{
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))
    explicit_bzero(p, n);
#else
    {
        volatile unsigned char *vp = (volatile unsigned char *)p;

        while (n--)
            *vp++ = 0;
    }
#endif
}

/* ---- 整页还内核：把明文页标记为可丢弃，内核立即回收物理页 ----
 * 比 memset 更强：memset 只是覆写内容，MADV_DONTNEED 让内核丢掉页映射，
 * 攻击者即便有旧映射也读不到（重新访问会得到零页）。
 * 注意：仅对匿名页有效，粒度 4K，调用方需确保区间内无其他活跃数据。 */
#include <sys/mman.h>
static int v7_wipe_region(void *addr, size_t len)
{
    unsigned long pg = 4096UL;
    unsigned long a = ((unsigned long)addr + pg - 1) & ~(pg - 1);
    unsigned long e = ((unsigned long)addr + len) & ~(pg - 1);

    if (e <= a)
        return 0;
    /* MADV_DONTNEED：内核丢页；重新访问返回零页（对匿名映射） */
    if (madvise((void *)a, e - a, MADV_DONTNEED) == 0)
        return 0;
    /* 回退：至少把内容擦掉 */
    v7_wipe_mem((void *)a, e - a);
    return -1;
}

/* ---- argv 传参链擦除（r22 新增）----
 * 背景：脚本明文经 argv 层层传递（用户 → wrap → elfrun → 内层 bash），
 * 每层都留一份拷贝。execve 成功后调用本函数擦掉自己这层的残留。
 * 只擦 string 内容，不 free（argv 数组本身归 libc/内核管）。 */
static void v7_argv_wipe(int argc, char **argv)
{
    int i;

    if (!argv)
        return;
    for (i = 0; i < argc; i++) {
        if (argv[i])
            v7_wipe_mem(argv[i], strlen(argv[i]));
    }
}

/* ---- 第一层：断读加固（r22）----
 * 在完成全部采样验证后再调用（调用后自身也无法 dump，故放最后）。
 * 返回：0 成功；负数表示部分失败（非致命，继续执行）。 */
#include <sys/prctl.h>
#include <sys/mman.h>
#include <errno.h>
#ifndef PR_SET_DUMPABLE
#  define PR_SET_DUMPABLE 4
#endif
#ifndef MADV_DONTDUMP
#  define MADV_DONTDUMP 16
#endif

static int v7_harden_memory(void *sensitive, size_t len)
{
    int rc = 0;

    /* ① 关闭 core dump + /proc/pid/mem 可读性
     * 效果：非 root 完全读不了；root 需绕过 SELinux（LKM 除外）
     * 这是对付"多线程高频轮询 dump"的唯一解——读都读不了，轮询无意义 */
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
        rc = -1;

    if (sensitive && len) {
        /* ② 标记敏感区不进 core dump（gcore 会被内核跳过） */
        if (madvise(sensitive, len, MADV_DONTDUMP) != 0)
            rc = -2;
        /* ③ 锁定物理页，防 zram/swap 换出到磁盘（换出=落盘=可被离线分析）
         * 失败不致命（RLIMIT_MEMLOCK 可能不足），只记录 */
        (void)mlock(sensitive, len);
    }

#ifdef MADV_WIPEONFORK
    if (sensitive && len)
        /* ④ fork 时子进程看到零页，防"fork 后慢慢 dump" */
        (void)madvise(sensitive, len, MADV_WIPEONFORK);
#endif
    return rc;
}

#endif /* V7_WIPE_H */
