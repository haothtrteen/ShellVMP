# V7 设计：ELF 封装层

> **核心目标**：让磁盘上**永不存在完整明文**，让运行期的明文窗口尽可能短且有界。

---

## 一、双路线

| 路线 | 结构 | 明文窗口 | 结论 |
|---|---|---|---|
| **A：外挂 ELF** | 父进程解密 + 子进程解释器 | 跨进程（pipe/memfd） | 实现简单 |
| **B：魔改解释器内嵌** | **单进程** | **最小** | **能单进程就单进程** |

> **"能单进程就单进程"** 是本项目在 V7 阶段最重要的结论。
> 多进程的进程间通信**必然**是可攻击的明文窗口。

---

## 二、载荷布局（blob v3）

```
[ct][tag 16][salt 16][N 4 LE][wb_table 256][wb_perm 256][wb_mask 256][flags 4 LE][len 4 LE]

len = ctlen + 812
```

**定长尾读**：从文件尾反向定位，不依赖头部偏移（头部可能被工具改写）。

两种模式（口令模式 / 白盒模式）**共用布局**——口令模式下白盒三表填随机诱饵。

---

## 三、密码学

```bash
kenc = HMAC(seed, "V7ENC")     # 域分离标签
kmac = HMAC(seed, "V7MAC")

流密钥块 i = HMAC(kenc, be64(i))[32B]
tag        = HMAC(kmac, ct)[16B]      # Encrypt-then-MAC
```

### scrypt-like KDF

```
PBKDF2  →  ROMix(N=131072 → 16MB 顺序填充 + 随机回访)  →  PBKDF2
```

**内存硬**：攻击者无法用少量内存加速，必须付出 16MB 的实际内存访问。

**注意**：`scrypt_blockmix` 是**原地**调用（别名效应）——编译端与运行端必须一致。

### 白盒解码

```
v7_wb_decode：256 字节表 + perm + mask
把"grep 连续 32 字节 seed"变成"分析 256 字节表的双射结构"
```

### per-build 标签随机化

| 开关 | 效果 |
|---|---|
| `V7_RAND_LABEL=1` | 每次构建换一组标签（跨样本 yara 失效） |
| `V7_LABEL_OBF=1` | 标签 XOR 存储（单样本 `strings` 也失效） |

---

## 四、流式执行（路线 B）

```
父进程:
  分块（4096）解密 → 写 pipe
  ★ 即写即抹 —— 明文不进磁盘，内存驻留量最小
  ★ 每次 write 前：waitpid(WNOHANG|WUNTRACED) + child_being_traced

子进程:
  exec 魔改 bash，读 /proc/self/fd/N
```

### 对抗 "SIGSTOP 冻结 + 管道排空"

**攻击手法**：攻击者 `SIGSTOP` 子进程，让父进程把明文全部写进 pipe，然后慢慢读。

**三重对抗**：

| 手段 | 作用 |
|---|---|
| `waitpid(..., WUNTRACED)` | 检测子进程被冻结 |
| 写端 `O_NONBLOCK` | 不阻塞，立即发现异常 |
| `F_SETPIPE_SZ` 缩到**一页（4K）** | 缓冲区小 → 明文驻留量最小 |

---

## 五、反调试五件

| 检测 | 手段 | 退出码 |
|---|---|---|
| TracerPid | 读 `/proc/self/status` | 113 |
| 注入 | 扫 `LD_PRELOAD` | 113 |
| 时间窗 | 解密耗时 > 3000ms（**VMP 构建下关闭**） | 113 |
| frida | 扫自身 maps 的 frida 痕迹 | 113 |
| 执行期 | 轮询子进程 TracerPid | 113 |

### 为什么 VMP 构建要关时间窗

```
VM 解释执行天然慢 10-100 倍
→ 与"调试导致的停顿"不可区分
→ 必然误杀
```

**原则**：**检测"时间"这类间接指标必须在 VMP 构建下关闭。**
**要检测就检测确定性事实**（TracerPid / maps / 内部 flags）。

---

## 六、内存擦除三层纵深（`v7_wipe.h`）

| 层 | 手段 | 边界 |
|---|---|---|
| **1** | `PR_SET_DUMPABLE=0` | 非 root 断读；**root 可绕** |
| **2** | seccomp-BPF 黑名单 | 拦 `ptrace`/`process_vm_readv`/`process_vm_writev`；**各架构 syscall 号不同** |
| **3** | `mlock` + `MADV_DONTDUMP` + `MADV_WIPEONFORK` | 防换页 / 防 core / 防 fork 泄露 |

### seccomp 各架构 syscall 号

| 架构 | ptrace | process_vm_readv | process_vm_writev |
|---|---|---|---|
| x86_64 | 101 | 310 | 311 |
| aarch64 | 117 | 270 | 271 |
| i386 | 26 | 347 | 348 |
| arm | 26 | 376 | 377 |

**两个设计选择**：

1. **命中返回 `EPERM` 而非 `KILL`** —— 便于观察攻击者行为
2. **fail-open** —— 加固失败不中断执行（可用性优先）

**手写 BPF 字节码**（不链 libseccomp）——Android NDK sysroot 没有该库。

---

## 七、退出码

| 码 | 含义 |
|---|---|
| `113` | 反调试命中 |
| `114` | 完整性 / MAC 失败 |
| `121` | 裸环境缺工具 |

---

## 八、实测打脸清单

| 我以为 | 实测 |
|---|---|
| `PROT_NONE` 拦不住 `/proc/pid/mem` | ❌ 内核走 `get_user_pages`，**不检查页表权限** |
| `unset` 能擦内存 | ❌ 密文留 5 份副本、明文留 8 份递减前缀 |
| "窗口式保护"有用 | ❌ 8 线程轮询**命中率 99.9995%** |
| `free` 后就干净 | ❌ chunk 复用，擦过的零被覆盖 |

**r28 的修法**：`isa_dec_at` **逐字段按需解密到栈上**，**根本不产生整段明文**。

---

## 九、检测下沉

**为什么检测要下沉到 C 层内部 flags**：

```c
// 环境变量可伪造，C 层内部 flags 不可
which_set_flags() 直读内部状态
```

这是**魔改解释器才有的能力**——外挂加载器做不到。

---

## 十、毒化 > 报警

```bash
# 环境指纹命中时，不 exit，而是把密钥链毒化
[ "$_pm" = 1 ] || _mk="${_mk}q"    # 静默破坏
```

**为什么**：

| 策略 | 攻击者反应 |
|---|---|
| 报警（退出） | "我 patch 掉这个检测就好了" |
| **毒化（正常跑但结果错）** | "**我的方法是不是错了？**" |

**报警可绕，破坏不可绕。**

---

## 十一、相关文档

| 主题 | 文档 |
|---|---|
| 令牌化实现 | [`TOKENIZATION.md`](TOKENIZATION.md) |
| 构建与退出码 | [`BUILD.md`](BUILD.md) |
| 踩坑清单 | [`PITFALLS.md`](PITFALLS.md) |
