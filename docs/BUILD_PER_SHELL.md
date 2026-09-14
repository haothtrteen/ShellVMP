# 各 shell / 平台的 C 层构建法

> 本文回答一个问题：**同一套 C 层补丁（`isa_hook.c` + `v7core.c` + `v7_builtin_takeover.c` +
> `v7_harden.c` + `zread.c.v7poc`）怎么挂到不同的解释器上。**
>
> 结论先行：**bash 与 mksh 两棵树都已实测打通**（产物与 plaintext 逐字节一致）；
> 其它解释器按各自的 builtin 注册机制如法炮制。libc 侧 Android 只有 bionic 一条
> 路能走通，见 §4。

---

## 一、先分清三条产物线

搞错线是最高频的时间黑洞（本项目实际烧掉过一整天）。三者的**能力与代价**是物种差异，
不是程度差异：

| 线 | 产物形态 | VMP 令牌化 | 宿主要求 | 入口 |
|---|---|---|---|---|
| **bash 线（最强）** | 改过的 bash 二进制（密文骨架内嵌尾部） | ✅ 有 | 必须自控宿主（要带自己的 bash） | `v7/v7_build.sh` |
| **ELF 线** | `elfrun` + 内嵌静态 bash | ❌ 无 | 不依赖 C 层，落地即用 | `v7/v7_build.sh`（`V7_MODE=elf`） |
| **纯脚本线** | V6 产物 / `v7_wrap.sh` 自释放 | ❌ 无 | 只要宿主有 bash **或** mksh | `v6/shell_script_obfuscator_v6.sh` |

纯脚本线**天然原生兼容 bash 与 mksh**，因为它不含任何 C 层成分 —— 这条只能这么说，
不要把"兼容所有 shell"写上去（见 §5 的实测矩阵）。

---

## 二、两个互斥的分发模式（先选对，再谈构建）

| 模式 | 触发条件 | seed 来源 | 运行期要求 |
|---|---|---|---|
| **口令模式** | 给了 `V7_OUTER_PASS` / `V7_PASS` | `scrypt(pass + salt)` | 必须提供口令 |
| **离线模式** | 不给口令 | 随机 seed → **白盒三表**编码 | **无需口令** |

两者**互斥**。用口令打的包，运行期一定要口令；不加口令就是离线白盒。
"离线模式要口令"这个报错 100% 说明**用了口令模式在打包**，不是离线模式坏了。

离线模式的最小可用命令（实测通过）：

```sh
V7_BASH_BIN=./workspace/v7_aarch64_bionic/bash-vmp-aarch64-bionic-r33 \
V7_WRAP=1 V7_KEEP_STAGE=1 \
bash v7/v7_build.sh app.sh app.bash
```

---

## 三、三个构建入口（**别用错**）

| 入口 | 定位 | 注意 |
|---|---|---|
| `v7/v7_build.sh` | ★ **统一入口** | 支持两种模式；认 `V7_MODE=bash\|elf`、`V7_WRAP`、`V7_KEEP_STAGE`、`V7_ISA_PARAM` |
| `v7/bash_poc/v7bash_build.sh` | bash 线内部、**口令专用** | 日志里那句"离线分发模式"是继承下来的样板文字，它**不实现白盒** |
| `v7/bash_poc/build_poc.sh` | 在 bash 源码树里**重建改过的 bash** | 唯一正确的重编入口，它会把下面所有注入做全 |

---

## 四、C 层怎么挂上去（bash 树，逐条）

`build_poc.sh` 做的事，按**必须齐全**的顺序列在这里。少任何一条的症状都写在括号里。

### 4.1 换掉/新增 C 源

```sh
cp $HERE/zread.c.v7poc  $SRC/lib/sh/zread.c          # ← 不是 zread.c.patch！见 §7
cp $HERE/v7core.c       $SRC/lib/sh/v7core.c
cp $HERE/isa_hook.c     $SRC/lib/sh/isa_hook.c
cp $HERE/v7_builtin_takeover.c $SRC/lib/sh/v7_builtin_takeover.c
cp $HERE/v7_harden.c    $SRC/lib/sh/v7_harden.c
cp $HERE/v7_isa_syms.h  $SRC/lib/sh/v7_isa_syms.h    # sym id → 真名
cp $HERE/v7_isa_key.h   $SRC/lib/sh/v7_isa_key.h     # 表加密主密钥（换它=既有表全废）
cp $SRC/../crypto_core.h $SRC/lib/sh/crypto_core.h
cp $HERE/crypto_isa.h   $SRC/lib/sh/crypto_isa.h     # 保留 static 的副本，专供 isa_hook.c
```

> **为什么两份 crypto 头**：`build_poc.sh` 会把 `crypto_core.h` 里 5 个函数的 `static`
> 去掉（VMPacker 要定位 local 符号）。若 `isa_hook.c` 也用这份，`v7core.o` 与
> `isa_hook.o` 会**各导出一份**同名全局 → `ld.lld: duplicate symbol`（实测 5 条）。
> `crypto_isa.h` 是同样的代码、保留 static，两份各自 local，互不撞车。

### 4.2 上游源码插桩（缺则"以为保护了其实没保护"）

```sh
python3 $HERE/xtrace_kill.py  $SRC/print_cmd.c $SRC/y.tab.c $SRC/make_cmd.c $SRC/shell.c
python3 $HERE/getcwd_quiet.py $SRC/builtins/common.c
python3 $HERE/isa_hook.py     $SRC/execute_cmd.c $SRC/y.tab.c $SRC/variables.c $SRC/shell.c
```

> **`isa_hook.py` 是硬性必需步骤。** 忘了跑，表里的令牌就没人翻译，
> 运行期表现为 `v7p_89yg4fddx6: command not found`。脚本是幂等的，重复跑安全。

**插桩器现在是表驱动的**（B0 重构）。所有"往哪个文件的哪一行插什么"
都声明在 `v7/bash_poc/anchors.py` 的锚点表里，`isa_hook.py` 只负责读表执行。

```sh
# 新式（推荐）：指定解释器 + 源码树，锚点表自动决定改哪些文件
python3 $HERE/isa_hook.py --interp bash-5.2 --srcdir $SRC
python3 $HERE/isa_hook.py --list          # 列出全部锚点集
python3 $HERE/isa_hook.py --interp bash-5.2 --srcdir $SRC --dry-run   # 只报告不写盘
```

> 旧式 4 路径调用（`build_poc.sh` 在用的那种）**继续支持**，两种入口结果
> 已由 `tests/test_isa_hook_table.sh` 断言逐字节一致。

bash-5.2 锚点集的四个插桩点（对应 `isa_hook.c`）：

| 文件 | 位置 | 作用 |
|---|---|---|
| `execute_cmd.c` | `execute_simple_command` 内、首个分派读取前 | 命令词翻译（单点覆盖 builtin/external/function/execve 全路径）+ 全部参数词路径常量还原 |
| `y.tab.c` | `CHECK_FOR_RESERVED_WORD` **宏** | L3 保留字还原。**注意**：`find_reserved_word` 是旁路死代码，patch 它 = 全程不生效 |
| `variables.c` | `find_variable` 查表前 | L4 位置参数别名还原 |
| `shell.c` | `shell_initialize()` 之后 | 自定义 builtin 接管 + 抗 dump 加固安装点 |

**加一个新解释器 = 往 `anchors.py` 填一组 `ANCHOR_SET`**，不用改 `isa_hook.py`。
已有一个**试验性** mksh 锚点集（`mksh-R59c`，只做 L3，见下 §4.2.1）。

#### 4.2.1 mksh 锚点集（试验性，B1）

mksh 的保留字识别比 bash 干净：不是宏、不是编译期生成的数组，而是 `lex.c` 里
**一句** `ktsearch(&keywords, ident, h)` 查**运行期哈希表**。

| | bash | mksh |
|---|---|---|
| 保留字表形态 | 编译期生成 `word_token_alist` | 运行期哈希表 `keywords`（`syn.c:825 initkeywords()`） |
| 识别入口 | `CHECK_FOR_RESERVED_WORD` **宏**，两处展开 | `lex.c` **单点** `ktsearch` |
| 陷阱 | 旁边有形态酷似的**死函数** `find_reserved_word` | 无 |

插桩点选在 `memset(dp, 0, (ident + IDENT) - dp + 1);` 之后、
`if (*ident != '\0' && (cf & (KEYWORD | ALIAS))) {` 之前 ——
此刻 `ident` 已补零完成、即将被 `hash()`/`ktsearch` 消费。

**状态：只验证了「锚点表能定位并正确插入 + 编译通过 + 行为不变」，
尚未接入构建、尚未实现真正的翻译函数。** 用法：

```sh
python3 $HERE/isa_hook.py --interp mksh-R59c --srcdir <mksh源码树>
sh Build.sh -r        # 已验证：编译成功，基本语法功能与未插桩版一致
```

> ⚠️ **已知风险（未解决）**：mksh 的 `ident` 是**栈上定长数组**（上界为编译期
> 常量 `IDENT`）。ISA 别名长于原名时存在溢出风险。这是移植路线的**止损点**，
> 详见 [`C_LAYER_ROUTE_COMPARE.md`](C_LAYER_ROUTE_COMPARE.md) §A.6。

### 4.3 Makefile 注入（**必须三处齐全**）

```sh
# ① lib/sh 对象列表（少则 undefined reference to v7c_scrypt_kdf/... 一大串）
sed -i 's|itos.o zread.o zwrite.o shtty.o shmatch.o eaccess.o \\|itos.o zread.o zwrite.o shtty.o shmatch.o eaccess.o v7core.o isa_hook.o v7_builtin_takeover.o v7_harden.o \\|' lib/sh/Makefile

# ② 编译规则（target-specific flags 经占位注入；VMP 线要 -fno-inline）
sed -i "s|^zread.o: zread.c\$|zread.o: zread.c v7core.c\nv7core.o: v7core.c\n\t\$(CC) \$(CCFLAGS) ${V7CORE_FLAGS} -c \$(srcdir)/v7core.c\nisa_hook.o: isa_hook.c\n\t\$(CC) \$(CCFLAGS) ${ISA_HOOK_FLAGS} -c \$(srcdir)/isa_hook.c\nv7_builtin_takeover.o: v7_builtin_takeover.c\n\t\$(CC) \$(CCFLAGS) ${V7_BT_FLAGS} -c \$(srcdir)/v7_builtin_takeover.c\nv7_harden.o: v7_harden.c\n\t\$(CC) \$(CCFLAGS) ${V7_BT_FLAGS} -c \$(srcdir)/v7_harden.c|" lib/sh/Makefile

# ③ 链接库（少 -lcrypto 则 undefined reference to EVP_*/HMAC/PKCS5_PBKDF2_HMAC）
sed -i 's|^LIBS = .*@LIBS@.*|LIBS = $(BUILTINS_LIB) $(LIBRARIES) @LIBS@ -lpthread -lcrypto|' Makefile
```

### 4.4 `v6openssl` builtin（原生构建才注入）

`mkbuiltins` 是**从 `DEFSRC` + `OFILES` 两个地方驱动的**，只改一个会得到
`undefined reference to openssl_builtin`：

```sh
cp $HERE/v6openssl.def builtins/v6openssl.def
sed -i 's|complete\.def \$(srcdir)/mapfile\.def|complete.def $(srcdir)/mapfile.def $(srcdir)/v6openssl.def|' builtins/Makefile   # DEFSRC
sed -i 's|bashgetopt\.o complete\.o|bashgetopt.o complete.o v6openssl.o|' builtins/Makefile                                          # OFILES
```

> 交叉构建（aarch64）**跳过**它：`opensslconf.h` 是架构专属头，交叉时没有
> 对应的 `libssl-dev:arm64`，硬加会在编译期卡死整条线。该 builtin 目前也**未被
> V6 调用**（V6 的 aes 线走外部 `openssl` 命令），属死代码。

### 4.5 configure 参数（少 `--disable-nls` 会**静默跑不动 V6 产物**）

```sh
./configure --disable-readline --disable-nls --without-bash-malloc \
    CFLAGS="-g -O2 -fcommon $VMP_DEFS"
```

> **实测坑**：不带 `--disable-nls` 编出来的 bash，跑 V6 产物会在第一个块之后**静默
> `exit 1`（无任何输出）**，极易误判成"保护功能坏了"。加上即正常。见 §7.3。

---

## 五、mksh 树（R59c，已实测打通）

mksh 比 bash 好挂得多：**源码约 3 万行**（bash 约 150 万行），且自带
`TARGET_OS=Android` 原生路径。

### 5.1 关键差异

| 项 | bash | mksh |
|---|---|---|
| builtin 注册 | 静态 `shell_builtins[]` 数组 + `mkbuiltins` 从 `.def` 生成 | 运行期哈希表 `ktinit(APERM, &builtins, 7)`，公开 API `builtin(name, func)` |
| 挂载点 | `shell.c` 的 `shell_initialize()` 之后 | `main.c` 的 `mkshbuiltins[]` 循环**之后** |
| 插桩方式 | 四处 python patch | 直接 `builtin("v7probe", c_v7probe)` 一行 |

### 5.2 实测结果

```sh
$ ./mksh-inject/mksh -c 'v7probe'
V7PROBE-ACTIVE
$ ./mksh-inject/mksh -c 'v7eval magic-token'
V7-EVAL-INTERCEPTED
$ ./mksh-inject/mksh -c 'v7eval other'
V7-EVAL-PASSTHRU
$ ./mksh-inject/mksh -c 'type v7probe'
v7probe is a shell builtin
```

**V6 产物在 mksh 下运行，输出与 bash 逐字节一致**（含 `for` 循环、变量展开、
引号内含 `$var` 的字符串）：

```
S01 begin / S02 obfuscator / S03 信号=0 / S04 a,b,c / S05 has "quotes" and $vars
S06 end / power by haothtrteen / T33 done / over
```

### 5.3 挂载骨架

```c
/* main.c：紧跟在 mkshbuiltins[] 注册循环之后 */
extern int c_v7probe(const char **wp);
extern int c_v7eval(const char **wp);
...
    builtin("v7probe", c_v7probe);
    builtin("v7eval",  c_v7eval);
```

> 移植到**别的解释器**时，这套 C 层功能（V6 骨架 + ISA 表 + 几个内联命令魔改）
> 等价于「找到该解释器的 builtin 注册 API + 命令分发点」，插进去效果相同。
> 差别只在**插桩便利度**，不在能力。

---

## 六、Android libc 三条线（真机实测）

| libc | 结果 | 原因 |
|---|---|---|
| **glibc 静态** | ❌ `SIGSYS(31)` / rc=159 | Android O+ 的 zygote seccomp 白名单按 bionic `SYSCALLS.TXT` 生成；glibc 2.35+ 静态启动会发 `rseq`（arm64 #293） |
| **musl 静态** | ⚠️ 能跑，但白名单外的 syscall 仍 `SIGSYS` | 不是根因解 |
| **bionic 静态** | ✅ **正解** | clang + Android target + NDK sysroot：`--target=aarch64-linux-android28`，需 `/opt/bionic-shim/libgcc.a` |

Termux 本地构建走 `build_termux.sh`（`BASH_VER="5.2.37"`，镜像顺序 tuna → aliyun →
ustc → gnu），最后调 `build_poc.sh`。

---

## 七、排障清单（按"实际烧掉的时间"排序）

### 7.1 运行期 `v7p_xxx: command not found`
→ `isa_hook.py` 没跑（§4.2）。**换用 `zread.c.v7poc` 后必须重跑。**

### 7.2 运行期 `v7: 缺少 V7_PASS（产物需要外层口令）` / rc=114
→ 不是"离线模式没实现"，是**用了口令模式在打包**（§2）。不加口令即可。

### 7.3 V6 产物跑到某处**静默 exit 1，无任何输出**
→ 三条可能，按概率：
1. **configure 少 `--disable-nls`**（§4.5）—— 实测最容易中，重编即好；
2. `libsh.a` **陈旧**：`v7core.o`/`isa_hook.o` 在库里但 `v7_harden.o` 不在，
   链接期报 `undefined reference to v7_harden_install`。手工注入过 Makefile 的树
   特别容易中，`rm -f lib/sh/libsh.a && make` 即可；
3. 脚本本身 ≥10 块 → 见 §八，是**独立已知项**。

### 7.4 `zread.c.patch` vs `zread.c.v7poc`（**最高频的错**）
- `zread.c.patch`（2024-09-10）是**过时的 r10 实现**，KDF 是 20000 轮 HMAC 链
  （`v7_kdf`），里面**零个 scrypt**。
- `zread.c.v7poc`（2024-09-11）是**现行整文件版**，用 `v7c_scrypt_kdf` + 白盒
  `v7c_wb_decode`，`V7_FLAG_PASSMODE` 切模式。
- 构建侧 `v7_embed.py` 用的是 `scrypt_kdf`，**两端必须逐字一致**。用 `.patch`
  会得到 `v7: 外层口令错误或产物被篡改（HMAC 校验失败）` / rc=114 —— 而实际上
  口令是对的，只是 KDF 不是同一个。

### 7.5 别用 `ls` 判定"文件缺失"
`zread.c.v7poc` 曾被我 `ls` 判为不存在，实际全盘有 **6 份副本**。用 `find / -name`。

### 7.6 交叉架构在 x86 沙箱里跑不动
没有 `binfmt_misc` 的 aarch64 注册，`#!/bin/sh` wrapper 去 exec aarch64 ELF 会
`Exec format error`（rc=126）。**这不是产物 bug**。解法：把载荷抽出来直接喂 qemu：

```sh
sed -n '/^__V7_PAYLOAD_BEGIN__$/,/^__V7_PAYLOAD_END__$/{/^__V7_PAYLOAD/d;p;}' f \
  | base64 -d | gzip -dc > raw && chmod +x raw && qemu-aarch64-static ./raw args...
```

顺带可验证反汇编对抗：抽出的 ELF 报 `no section header`。

### 7.7 ISA 表 bin 与 json 必须同源
`isa_itest.py` 用 **json** 改写、二进制读 **bin**。两者不同源时会出现"改写对了、
还原错了"的假故障。改完表记得同步重导 bin。

---

## 八、已知边界（与构建无关，但会撞上）

- **≥10 块脚本静默 `exit 1`**：独立于 shell 的既有项（`docs/BACKLOG.md` §二）。
  9 块及以下实测与 plaintext 输出**逐字节一致**。
- **dash / zsh 不支持**：V6 产物用数组下标（`_nW[0]=...`），dash 报
  `cannot open`/rc=2，zsh 报 `assignment to invalid subscript range`。需标量-数组
  仿真层才可能打开（可能顺带修 busybox ash）。
- **保护面折损**（bash 线，为换 mksh 兼容）：`declare -f eval` → `command -V eval`，
  丢了 body 指纹检查；`<(...)` → `mktemp`，留了短暂明文落盘窗口。
- 退出码约定：113 环境异常；**114 完整性/认证（篡改与错口令故意不可区分）**；
  127 ISA 表破损/未配对；1 运行错误（刻意伪装成自然失败，不泄露保护痕迹）。

---

## 九、实测输出对照（验收基准）

以 9 块脚本为例，明文 / V6 产物在 bash 与 mksh 下**三者完全一致**：

```
S01 begin
S02 obfuscator
S03 信号=0
S04 a
S04 b
S04 c
S05 has "quotes" and $vars
S06 end
power by haothtrteen
T33 done
over
```

完整 V7 链路（V6 混淆 → bash 线封装 → 自释放）同样一致：

```sh
ANDROID_GATE=0 V7_BASH_BIN=<改过的 bash> V7_WRAP=1 V7_KEEP_STAGE=1 \
  bash v7/v7_build.sh app.sh app.bash
V7_SELF=1 sh app.bash /dev/null
```

v7_build.sh 日志中应出现 `分发模式 : 离线分发模式（白盒编码 seed）`，
且运行期**无 `command not found`、无 ISA 报错**。
