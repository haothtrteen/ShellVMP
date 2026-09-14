# mksh 线构建指南

> **本文回答**：我想用 mksh 魔改解释器打包保护我的 shell 脚本，**目录在哪、怎么构建、能得到什么**。
>
> bash 线的对应文档是 [`BUILD.md`](BUILD.md)；两条线的能力边界对照与选型建议见
> [`BUILD_PER_SHELL.md`](BUILD_PER_SHELL.md) §一 与本文件 §六。

---

## 一、先读这一段：mksh 线**当前能做什么**

**这一步不能跳过。** 选错线是最烧时间的错误（本项目为它烧掉过一整天）。

| 能力 | bash 线 | **mksh 线（当前）** |
|---|---|---|
| V6 产物执行 | ✅ | ✅ **与 bash 输出逐字节一致**（8 轮独立生成 8/8） |
| ISA 插桩 L1-L4（命令词/保留字/变量/路径令牌化） | ✅ | ✅ **四层已实装并验证** |
| L6 字符串字面量令牌化 | ✅ | ✅ **已实装**（出口在 `v7_builtin_takeover_mksh.c`） |
| C 层三件套（骨架密文注入 / v7core / builtin 接管） | ✅ | ✅ **已移植**（打开层劫持，见 §六.4） |
| **可作为"魔改解释器"打包受保护脚本** | ✅ | ✅ **已可**（一条命令出产物，见 §四 步骤 4） |
| **内层口令档**（`V7_PASS`） | ✅ | ❌ **暂不可用**（`read -p` 语义冲突，见 §6.3） |

> **一句话**：mksh 线**现在能打包了**，用**外层口令**（或离线分发模式）即可。
> 一条命令从明文脚本得到可执行产物：
>
> ```bash
> V7_MODE=mksh V7_MKSH_SRC=./mksh-src V7_OUTER_PASS='外层口令' \
>   bash v7/v7_build.sh your_script.sh app.mksh
> ```
>
> ⚠️ **暂时不要传 `V7_PASS`（内层口令）** —— 那会走到 V6 骨架的
> `read -rs -p 'Key: '`，而 `-p` 在 mksh 里是"从 coprocess 读"，
> 产物会 rc=1 失败（§6.3）。**外层口令 `V7_OUTER_PASS` 不受影响。**
>
> 你**不需要**先手工构建 mksh —— `[1/3]` 阶段会从 `V7_MKSH_SRC` 现场构建改版解释器。
>
> **另一条必须知道的契约**（详见 §六.3）：产物运行**必须带一个 argv 文件参数**
> （惯例 `/dev/null`）；产物是 ELF，要 `./app.mksh` **直接执行**，
> **不要**写成 `mksh app.mksh`。

§四 保留了**手工分步**的做法（当你想逐步看清每一环时用），
§五.4 是端到端验收方法（**打包后必须做对拍**）。

路线 C 的完整进度与挂载点勘察见
[`BUILD_PER_SHELL.md`](BUILD_PER_SHELL.md) §十。**如果只想先跑通保护**，
纯脚本线（V6 混淆器，零 C 层构建）仍然是最快的一条。

---

## 二、为什么值得为 mksh 单开一条线

不是"顺手多做一版"，而是**靶子判断**：

| 事实 | 含义 |
|---|---|
| Android 4.0（ICS）起 `/system/bin/sh` **就是 mksh**（5.0 起 ash 已移除） | 真机上不装 bash 也能跑的产物，长这样 |
| Termux 默认 shell 也是 mksh 系（可换 bash） | 移动端脚本环境的事实标准 |
| mksh 源码 **约 3 万行**（bash 约 150 万行） | 插桩、审计、编译都快得多 |
| mksh 自带 `TARGET_OS=Android` 原生构建路径 | 真机交叉编译友好 |
| mksh 保留字是**运行期哈希表 + 单点查表** | 插桩点比 bash 干净（bash 是宏 + 死函数干扰） |

---

## 三、环境要求

| 组件 | 要求 | 说明 |
|---|---|---|
| **C 编译器** | `gcc` / `clang` | mksh 只依赖 libc |
| **POSIX shell** | `sh` | 构建走 `Build.sh` |
| **python3** | 3.8+ | 锚点插桩器 |
| **cp / sed / make** | 标准工具 | — |
| **nm**（可选） | binutils | 产物校验用（`v7_shf_inject` 符号）；缺失时降级为警告 |
| **qemu-user-static**（交叉时必需） | — | ISA 段要用目标架构跑 `-n` 预检，见 §五.4 |

与 bash 线不同：**mksh 线不需要 openssl、不需要 autoconf**。`Build.sh` 是自带的轻量构建脚本。

> **`/tmp` 不可写的环境（Android / Termux）**：`v7mksh_build.sh` 开头会把 `TMPDIR`
> 归一化到一个可用目录，再交给下游（V6 的 `mktemp -d` 遵循 `TMPDIR`）。
> 你不需要手工设，但如果自己设了 `TMPDIR` 指向不可写目录，会在深处炸开。

---

## 四、构建流程

**两种用法，按你的目的挑**：

| 目的 | 走 | 章节 |
|---|---|---|
| **要一个能分发的受保护产物**（正常用法） | 一条命令 | **步骤 4**（推荐先读它） |
| 想逐步看清每一环 / 调试插桩 | 手工三步 + 打包 | 步骤 1→2→3→4 |

> 步骤 1-3 是**解释器构建**，步骤 4 是**打包**。走 `v7/v7_build.sh` 时前三步被内部自动完成。

---

### 步骤 1：取 mksh 源码

```bash
# 官方仓库（MirBSD）
git clone https://github.com/MirBSD/mksh.git mksh-src
cd mksh-src && git checkout mksh-R59c        # ★ 锚点集绑定 R59c，务必对齐

# 备选：从官方 tarball 展开
#   http://www.mirbsd.org/MirOS/dist/mir/mksh/mksh-R59c.tgz
```

> **版本必须对齐 `R59c`。** 锚点表的 `site_old` 是**逐字符匹配源码**的，
> 换了版本就会失败 —— 这是**刻意的响亮失败**（`isa_hook.py` 任一锚点不匹配即 exit 1），
> 不会静默改错位置。换版本 = 需要重新校准锚点（见 §七）。

### 步骤 2：运行锚点插桩

```bash
# 在 ShellVMP 仓库根目录执行
python3 v7/bash_poc/isa_hook.py --interp mksh-R59c --srcdir ./mksh-src

# 只看会改什么、不写盘（推荐先跑这个）
python3 v7/bash_poc/isa_hook.py --interp mksh-R59c --srcdir ./mksh-src --dry-run
```

**预期输出**（三个插桩点全部命中）：

```
>> 插桩目标：mksh-R59c（./mksh-src）
  lex.c ktsearch(&keywords) L3 翻译实装：应用
  exec.c findcom 入口 L1/L2 翻译实装：应用
  exec.c com_ex argv 数组 L4 路径还原实装：应用
ISA hook patch 全部应用（mksh-R59c）
```

插桩器**幂等**：重复跑会显示"已 patch，跳过（幂等）"，安全。

插桩还有一个**容易漏掉的前提**：光插桩不拷 C 层文件，编译必然 `undefined reference`。
手工走这条路的完整命令（★ 注意**改名**，锚点表按改后的名字 `#include`）：

```bash
cp -f v7/mksh_poc/v7core_mksh.c              mksh-src/v7core.c
cp -f v7/mksh_poc/v7_builtin_takeover_mksh.c mksh-src/v7_builtin_takeover.c
cp -f v7/mksh_poc/v7_shf_inject_mksh.c       mksh-src/v7_shf_inject.c
cp -f v7/bash_poc/isa_hook.c                 mksh-src/isa_hook.c
cp -f v7/bash_poc/crypto_isa.h               mksh-src/crypto_isa.h
```

以及把 `Build.sh` 的 `SRCS` 行扩上这四个 `.c`：

```sh
# Build.sh:611 原样
SRCS="$SRCS lex.c main.c misc.c shf.c syn.c tree.c var.c"
# 改成（★ 追加到行尾，保留原有内容）
SRCS="$SRCS lex.c main.c misc.c shf.c syn.c tree.c var.c isa_hook.c v7_builtin_takeover.c v7_shf_inject.c v7core.c"
```

> **为什么是追加而不是替换**：`Build.sh` 的 `SRCS` 在不同来源的树上形态不同
> （可能已含 `isa_hook.c`）。`v7mksh_build.sh` 用**捕获组正则**归一，逐项判断缺哪个加哪个
> —— 手工做时也建议照这个思路，别写死整行。

### 步骤 3：编译

```bash
cd mksh-src
TARGET_OS=Linux sh Build.sh -r        # Linux 宿主
# TARGET_OS=Android sh Build.sh -r    # 交叉/真机（需对应 NDK 工具链）

# 产物
ls -la mksh
```

**`-r` 不是可选项。** 它是"重新配置"（清 `obj/` 重跑 mirtoconf）。跨架构切换时
不带 `-r` 可能复用旧 `.o` **链接出混合架构二进制** —— 症状是"能编译，跑起来诡异崩溃"。

**实测基线**（x86_64 / gcc 13.3）：

| 树 | 产物大小 |
|---|---|
| 未插桩的原始 mksh | 338256 字节 |
| 插桩 + C 层三件套（本线产物） | 347888 字节 |

产物校验（**编译成功 ≠ 插桩进去了**）：

```bash
nm mksh-src/mksh 2>/dev/null | grep -q v7_shf_inject \
  || echo "错误：注入层未链接"
```

> ⚠️ **不要用 `[ -x mksh ]` 当门禁。** 交叉架构时宿主机本来就执行不了目标产物，
> `-x` 必为假 —— 用它会把"构建成功"误判成"构建失败"。判据用 `-f` / `-s`。

### 步骤 4：一条命令打包（★ 正常用法）

到这一步，前面三步（取源码 / 插桩 / 编译）**全部被自动完成**：

```bash
cd ShellVMP

# ① 现场构建改版 mksh + 打包（主路径）
V7_MODE=mksh V7_MKSH_SRC=./mksh-src \
  V7_OUTER_PASS='外层口令' V7_PASS='内层key' \
  bash v7/v7_build.sh your_script.sh app.mksh
```

`V7_MODE` 也可以省略 —— 输出后缀是 `*.mksh` 时自动判定为 mksh 线：

```bash
V7_MKSH_SRC=./mksh-src V7_OUTER_PASS='外层口令' \
  bash v7/v7_build.sh your_script.sh app.mksh
```

**已经构建过改版 mksh 时**，用 `V7_MKSH_BIN` 跳过构建（秒级重打包）：

```bash
V7_MODE=mksh V7_MKSH_BIN=/path/to/插桩后的/mksh \
  V7_OUTER_PASS='外层口令' \
  bash v7/v7_build.sh your_script.sh app.mksh
```

`V7_MKSH_SRC` 与 `V7_MKSH_BIN` **二选一**，都不给会响亮报错。

**日志应出现的关键行**：

```
[1/3] 构建改版 mksh（现场）...
[1.5/3] ISA 四层表 + L6 令牌化...
[2/3] V6 骨架...
[3/3] 加密嵌入 → app.mksh
```

**构建顺序与 bash 线相反（照抄 bash 线必死）**：

| 线 | 顺序 | 原因 |
|---|---|---|
| bash 线 | 先改写脚本 → 再构建解释器 | 改版 bash 由**调用者提供**，ISA 的 `-n` 预检用它跑 |
| **mksh 线** | **先构建解释器 → 再改写脚本** | mksh 由**本脚本现场构建**，预检必须用这个刚出炉的二进制 |

照抄 bash 线顺序会得到"预检时 mksh 还不存在"的死锁。ISA 段因此落在 `[1/3]` 之后。

**常用开关**（完整清单见 `bash v7/v7_build.sh -h`）：

| 变量 | 作用 |
|---|---|
| `V7_MKSH_SRC` / `V7_MKSH_BIN` | mksh 源码目录（现场构建）/ 已构建的改版 mksh |
| `V7_OUTER_PASS` | 外层口令；不给 = 离线分发模式（白盒 seed，运行免口令） |
| `V7_PASS` | 内层 passkey（V6 密钥分离） |
| `V7_ISA=0\|1` | ISA 四层 + L6 令牌化（默认 1）；`V7_ISA_SEED=N` 固定种子（复现用） |
| `V7_ARCH` / `V7_CC` | 目标架构 / 交叉编译器 |
| `ANDROID_GATE=0\|1` | **脚本侧**安卓环境门控（默认 1）；与目标架构无关，见 §六.5 |
| `V7_KEEP_STAGE=1` | 保留中间产物（**含明文语义等价物，勿分发**） |

**运行产物**（★ 契约在 §六.3）：

```bash
echo '内层key' | V7_SELF=1 V7_PASS='外层口令' \
  V7_ISA_TABLE=app.mksh.isa.bin ./app.mksh /dev/null
```

---

## 五、验证（**这一步必须做**）

### 5.1 ISA 四层端到端测试

```bash
# 生成一张测试表（四层 + L6）
python3 tools/v7_isa.py gen --seed 20260914 -o /tmp/t.bin --json /tmp/t.json

# 跑集成测试（--bash 参数接受任意解释器路径）
python3 tools/isa_itest.py --bash ./mksh-src/mksh --table /tmp/t.bin --json /tmp/t.json
```

**预期结果**（实测基线）：

```
PASS simple             命中 1 项
PASS l3_structures      命中 14 项
PASS grow_token         命中 4 项
PASS recursive_lex      命中 12 项
PASS l4_path            命中 5 项
PASS quoted_and_comment 命中 3 项
------------------------------------------------------------
合计：6 PASS / 0 FAIL
```

### 5.2 回归套件（确认插桩零副作用）

```bash
cd mksh-src && ./test.sh
```

**关键判据不是"通过多少"，而是"与未插桩基线逐项 diff 完全一致"。**
实测基线：**535 pass / 33 fail**，33 项为 tty/history/env-prompt 类环境性失败，
与未插桩 mksh 的失败清单**逐项相同** ⇒ 插桩零副作用。

> 只报"535 pass"而不做基线对比是不够的 —— 插桩可能悄悄坏掉某几项，
> 又被另几项偶然补偿。**逐项 diff 才是证据。**

### 5.3 验证原则

> **唯一可靠的验证是"逐字节对拍"**（原脚本 vs 产物：rc + stdout + stderr）。

"能跑通"和"结果正确"在混淆系统里是两件完全不同的事。

### 5.4 端到端打包验证（**打包后必做**）

打完包不要只看"产物存在"。下面三项证据各自独立，都要过。

**证据 1：逐字节对拍**（唯一可靠的功能判据）

```bash
# 参照：明文脚本直接给 mksh 跑
ref=$(ANDROID_GATE=0 mksh your_script.sh 2>&1; echo "rc=$?")
# 产物：带 argv（/dev/null）跑
new=$(V7_SELF=1 V7_PASS='外层口令' V7_ISA_TABLE=app.mksh.isa.bin \
      ./app.mksh /dev/null 2>&1; echo "rc=$?")
[ "$ref" = "$new" ] && echo PASS || diff <(echo "$ref") <(echo "$new")
```

三元组对拍：**rc + stdout + stderr**，缺一不可。

> ⚠️ **先确认你构建的是哪个口令档**：内层口令档（`V7_PASS` 非空）目前有
> `read -p` 问题（§6.3），**会 rc=1 失败**。做对拍请先用**无内层口令档**
> （只给 `V7_OUTER_PASS`，不给 `V7_PASS`），跑出来应是 `PASS`。

**证据 2：字节账目**（独立于"能不能跑起来"的完整性判据）

```
产物大小 − 改版 mksh 大小 == 骨架大小 + 812
                               └─ V7_BLOB_OVERHEAD，两线共用
```

`812` 可用尾部长度字段独立复核：

```bash
tail -c 4 app.mksh | od -An -tu4     # 应等于 骨架大小+812
```

实测锚点：`348850 − 347888 = 962 = 150 + 812`。

**blob v3 布局（两线逐字节一致）**：

```
[ct][tag 16][salt 16][N 4 LE][wb_table 256][wb_perm 256][wb_mask 256][flags 4][len 4]
 │    │        │        │          └─────────── 白盒三表（离线分发模式用）───────────┘
 │    │        │        └ scrypt 内存参数
 │    │        └ KDF salt
 │    └ HMAC 标签（Encrypt-then-MAC）
 └ 密文（长度 = len − 812）
```

`len = ctlen + 812`，`812 = 16+16+4+256×3+4+4`（见 `v7/bash_poc/v7_embed.py`
的 `OVERHEAD`）。**两线共用同一常量** —— 所以 bash 线的算账法可以直接搬过来。

**证据 3：磁盘无明文**

```bash
grep -c '你的脚本里的某个独特字符串' app.mksh    # 应为 0
```

**证据 4：错误路径必错**（防"恒 0 的检查"）

| 注入故障 | 期望 |
|---|---|
| 源码不是 R59c | exit 1 + 版本提示 + clone 命令 |
| 篡改 `Build.sh` 的 `SRCS` 行 | exit 1 + 打印实际行 |
| 翻转产物密文区字节 | **rc=114**（认证失败，不是 segfault） |
| 不带 `/dev/null` 跑产物 | rc=0 零输出（**契约，非缺陷**，见 §六.3） |
| 跨架构 + 无 qemu + `V7_ISA=1` | exit 1 + 三条出路（绝不静默跳过预检） |

> **幂等验证不要用 hash**：ISA 表刻意随机化（"掺假条目"），且 L6 令牌名每构建随机
> —— 两次构建的 hash **必然不同**。要比就比"改写版脚本 + 产物运行输出"，两者才稳定。

---

## 六、能力边界与排障

### 6.1 当前边界（诚实版）

| 现象 | 原因 | 状态 |
|---|---|---|
| ~~无法用 mksh 打包受保护脚本~~ | C 层三件套 | ✅ **已解决**（C1/C2/C3） |
| ~~`L6` 字符串令牌不解密~~ | L6 出口需 builtin 接管 | ✅ **已解决**（`v7_builtin_takeover_mksh.c`） |
| **内层口令档（`V7_PASS`）产物不可用** | `read -p` 在 mksh 是"从 coprocess 读" | ❌ **未修复**（见 §6.3 / §6.3b）→ 暂用无内层口令档 |
| elf 线 + 内嵌 mksh 静默无输出 | pipe 短读语义不兼容 | 已定位；mksh 线的 `shf_open()` 方案**已绕开**（见 §六.4） |
| 跨架构（aarch64）实测 | 需 qemu-user-static 跑 ISA 预检 | 代码路径已就位，**未实测** |
| `V7_WRAP`（自释放包装） | 尚未接入 mksh 线 | 见路线 C / C4 |

### 6.2 排障速查

| 症状 | 先查 |
|---|---|
| `错误：<op> 锚点不匹配（mksh 源码结构已变？）` | 源码版本不是 **R59c**（§四 步骤 1） |
| 插桩后编译报未声明符号 | `isa_hook.c` / 三个 `*_mksh.c` 未拷进源码树（§四 步骤 2） |
| `错误：Build.sh SRCS 缺 v7_shf_inject.c` | `Build.sh` 的 `SRCS` 只加了一部分 —— 幂等判据必须**逐项**判断 |
| 编译通过但产物运行无解密行为 | `nm` 查 `v7_shf_inject`；缺失 = C2 注入层未链接（§四 步骤 3） |
| **产物静默 rc=0、零输出** | **多半是没带 `/dev/null`**（§六.3）—— 先排除这条再查加密 |
| 产物输出里能看到 `v7p_xxx` 令牌 | 忘了 export `V7_ISA_TABLE=app.mksh.isa.bin`（§六.3 第三条） |
| ISA 测试全 FAIL，无命中 | 表 bin 与 json **不同源** —— 改表后忘同步重导 bin |
| 跨架构构建报"需要 qemu" | 装 `qemu-user-static`，或同架构构建，或 `V7_ISA=0`（降保护） |
| 产物在 mksh 下与 bash 输出不一致 | 跑 `sh tools/sh_compat_check.sh <产物.sh> [原脚本]` |

### 6.2b `ANDROID_GATE` 与 `TARGET_OS=Android` 别搞混

两者名字像，**作用域完全不同**：

| 开关 | 作用域 | 含义 |
|---|---|---|
| `ANDROID_GATE=0\|1` | **脚本侧**（V6 注入的代码） | 产物启动时的**环境门控**：非安卓直接静默拒绝 |
| `TARGET_OS=Android` | **C 侧**（mksh 构建分支） | mksh 的**平台/构建环境**（syscall/头文件兼容） |

> **关键：`TARGET_OS=Android` 本身不产生交叉编译。** 实测 `Build.sh:657-659` 把
> `Android` **归一化成** `Linux` —— 真正的交叉编译靠 `CC` / 工具链（`V7_CC`）。
> 也就是说：以为"设了 `TARGET_OS=Android` 就是编译安卓版"是**错的**。

### 6.3 ★ 运行契约（**最容易误诊的一条**）

**产物必须带一个 argv 文件参数，惯例是 `/dev/null`。**

```bash
./app.mksh /dev/null      # ✅ 正确
./app.mksh                # ❌ 见下方"不带 argv 的真实行为"
```

**为什么**：不带参数时 mksh 进入 **stdin 模式（`FSTDIN`）**，
`main.c:532` 的 `shf_open()` 分支**根本不会被走到** ⇒ 解密层不触发。

> **这是契约，不是缺陷。** 症状与"解密失败""完整性拒绝"**极易混淆**，
> 本项目在 C2 阶段为此烧过时间。构建脚本的收尾提示、`v7_build.sh -h`、
> 本文档三处都写了这一点。

**「不带 argv 的真实行为」取决于内层口令档**（2026-09 C3-f 复验实测）：

| 档位 | 不带 argv 的实测行为 |
|---|---|
| **无内层口令**（`V7_PASS` 留空） | **静默 rc=0、零输出** |
| **有内层口令**（`V7_PASS` 非空） | **rc=127 + 报错**：mksh 把 stdin 的内容当成**脚本名**去解析 |

```bash
# 有内层口令时，不带 argv 实测：
$ echo 'InnerPass123' | V7_SELF=1 V7_PASS='OuterPass123' ./app.mksh </dev/null
./app.mksh: <stdin>[1]: InnerPass123: inaccessible or not found
rc=127
```

> ⚠️ **有内层口令档目前还有第二个问题**（同批复验发现）：
>
> ```bash
> $ echo 'InnerPass123' | V7_SELF=1 V7_PASS='OuterPass123' ./app.mksh /dev/null
> /dev/null[56]: read: -p: no coprocess
> rc=1
> ```
>
> 根因是 V6 骨架里的 `IFS= read -rs -p 'Key: '` —— **`-p` 在两个 shell 语义相反**：
> bash 是"prompt 字符串"，mksh 是"从 **coprocess** 读"。见 §6.3b 第 6 项。
> **当前建议：mksh 线暂用无内层口令档**（外层口令 `V7_OUTER_PASS` 仍然有效）。

**第二条契约：产物是 ELF，要"直接执行"，不要写成 `mksh app.mksh`**：

```bash
./app.mksh /dev/null          # ✅ 直接执行 —— /proc/self/exe 指向产物自身
mksh app.mksh /dev/null       # ❌ /proc/self/exe 指向解释器，解密必然不触发
```

**第三条：带 ISA 表运行时**要显式导出表路径（表不嵌在产物里）：

```bash
V7_ISA_TABLE=app.mksh.isa.bin ./app.mksh /dev/null
```

漏掉表令牌会**照原样漏出**（实测可见 `v7p__gngvbzsi9` 这类令牌）—— 这是
"保护静默降级"，不是崩溃。

### 6.3b 已知的 mksh 语义陷阱（生成器侧已处理，但改产物时会撞上）

| 构造 | bash | mksh |
|---|---|---|
| `$_` | 上一条命令的最后一个参数 | **恒为 shell 自身路径** |
| `$RANDOM` | Park-Miller | 不同序列 |
| `$-` | 含 `h`/`B` 等标志位 | 不同标志集 |
| `read -a` | 数组 | 语义不同 |
| `shift` 无参数且位置参数为空 | 语句非零、脚本继续 | **当场终止脚本，rc=1** |
| **`read -p`** | **prompt 字符串** | **从 coprocess 读** ⇒ `read: -p: no coprocess`（**未修复**） |

> **倒数第二条踩过一次真雷**：V7 骨架第一行的 `[ -n "$V7_SELF" ] && shift`
> 在"无用户参数"时让 mksh **当场静默退出**，症状与"解密失败/完整性拒绝"
> **完全无法区分**（都是静默 rc）。已加 `[ "$#" -gt 0 ]` 守卫。
> 这类"跨解释器语义分叉伪装成加密故障"的坑，见 [`PITFALLS.md`](PITFALLS.md)。

> **最后一条（`read -p`）是 2026-09 复验新发现的，且尚未修复** ——
> 它只影响**内层口令档**（见 §6.3）。这同时说明上面这张清单**并非穷举**：
> 每加一个新档位，都要重新按"骨架里用到的每个内建/选项"过一遍语义对照。

### 6.4 本线为何劫持"打开层"而非"读取层"

这是 mksh 线与 bash 线的**有意设计差异**，不是偷懒：

| | bash 线 | **mksh 线** |
|---|---|---|
| 劫持位置 | **读取层**（`lib/sh/zread.c` 整文件替换） | **打开层**（`shf_open()`，`shf.c:51`） |
| 做法 | 边读边解密，明文逐块过境、即写即抹 | 检测受保护脚本 → 现场解密进 **memfd** → 让 shf 从 memfd 读 |
| 读取语义 | 被改写 | **完全不动** |
| 顺带收益 | — | **绕开 elf 线的 pipe 短读阻塞项**（见 [`BUILD_PER_SHELL.md`](BUILD_PER_SHELL.md) §10.3） |

`shf_open()` 之所以是个好挂点：全树只有 **5 个调用者**，其中只有 2 个是脚本入口
（`main.c:532` 主脚本、`main.c:758` `include()`），其余是重定向输入/历史文件/杂项。

**安全边界折损（诚实记录）**：memfd 可被**同 uid 进程**通过 `/proc/PID/fd/N` 读到；
且明文在一次 malloc 里**完整存在**（不像 bash 线那样逐块即写即抹）。
这是为换取"读取语义零改动 + 绕开短读"付的代价。

---

## 七、换版本 / 加插桩点

**加一个新解释器 = 往 `v7/bash_poc/anchors.py` 填一组 `ANCHOR_SET`**，不用改 `isa_hook.py`。

```bash
python3 v7/bash_poc/isa_hook.py --list          # 列出全部锚点集
```

mksh 锚点集（`MKSH_R59C`）实际有 **6 个 op**，不是 3 个 —— 因为它**已内置 C1/C2 的挂载点**：

| # | 文件 | 作用 |
|---|---|---|
| 1 | `lex.c` | L3 关键字翻译 |
| 2 | `exec.c` | L1/L2 命令位翻译 |
| 3 | `exec.c` | L4 路径常量还原 |
| 4 | `main.c` | **C1** extern 声明 |
| 5 | `main.c` | **C1** 初始化挂载 + builtin 接管 |
| 6 | `shf.c` | **C2** 骨架注入层 |

> **重要推论**：跑一次 `isa_hook.py --interp mksh-R59c --srcdir` 就**同时**得到
> ISA 插桩 **和** C1/C2 挂载点。所以**插桩与拷 C 文件是强耦合的** ——
> 只插桩不拷 C 文件，必然 `undefined reference`（§四 步骤 2 已给出拷贝命令）。

两条硬约束（源码考古结论，改前必读）见 [`BUILD_PER_SHELL.md`](BUILD_PER_SHELL.md) §4.2.1。

---

## 八、目录自包含性（**分发前必查**）

> 验收标准：**用户拿到的目录必须能独立走通"下载 → 构建 → 得到产物"，不依赖仓库其它部分。**

### 8.1 实测依赖关系

| 构建脚本 | 需要的外部文件 | 是否需随 mksh 线分发 |
|---|---|---|
| `v7/bash_poc/isa_hook.py` | `v7/bash_poc/anchors.py`（同目录） | ✅ 必须 |
| `v7/bash_poc/anchors.py` | 无（纯数据，零 import） | ✅ 必须 |
| `v7/bash_poc/isa_hook.c` | `crypto_isa.h`、`v7_isa_syms.h`、`v7_isa_key.h` | ✅ 必须 |
| `tools/v7_isa.py` | `v7/bash_poc/v7_isa_key.h`（相对脚本定位，可用 `V7_ISA_KEY_H` 覆盖） | ✅ 必须 |
| `tools/isa_itest.py` | 无跨目录依赖 | 测试用 |
| `v7/bash_poc/v7bash_build.sh` | `../../v6/shell_script_obfuscator_v6.sh` | ✅ 必须 |
| `v7/v7_build.sh` | `../tools/v7_isa.py`、`../v6/…`、`../tools/v6_lint.py` | ✅ 必须 |
| **`v7/mksh_poc/v7mksh_build.sh`** | 上列共享工具（走 `../bash_poc/`）+ **`v7/mksh_poc/` 下的三个 `*_mksh.c`** | ✅ 必须 |
| **`v7/mksh_poc/v7_shf_inject_mksh.c`** | `v7core.c`（包装层）→ `crypto_isa.h` | ✅ 必须 |
| **`v7/mksh_poc/v7_builtin_takeover_mksh.c`** | `crypto_isa.h`（L6 出口） | ✅ 必须 |
| **`v7/mksh_poc/v7core_mksh.c`** | `crypto_isa.h`（**不是** `crypto_core.h`） | ✅ 必须 |

> **目录布局**：`v7/mksh_poc/` 与既有的 `v7/bash_poc/` **平级**。
> 三个 `*_mksh.c` 是 mksh 线专属，所以随构建脚本一起放在 `mksh_poc/` 下；
> 而 `isa_hook.py` / `anchors.py` / `isa_hook.c` / `crypto_isa.h` / `v7_embed.py`
> 是**两线共用**的（表驱动、载荷无关），仍留在 `bash_poc/` 下，由
> `v7mksh_build.sh` 以 `$SELF_DIR/../bash_poc/xxx` 引用。
>
> **共享工具留在 `bash_poc/` 下的原因**：把 `bash_poc/` 换个父目录要同步改
> `tools/v7_isa.py` 的路径常量、`v7_build.sh` 3 处、`tests/test_isa_hook_table.sh` 2 处、
> README 结构树，以及 `bash_poc` 内部每个脚本的 `../../` 相对深度 ——
> **漏一处就是静默路径失效**。收益不值。

### 8.2 实测结论：**当前 8 个文件即可自包含**

把上表前 5 项复制到一个**空的隔离目录**（无仓库其它部分），实测结果：

| 验证项 | 结果 |
|---|---|
| 锚点插桩 `--dry-run`（`--interp mksh-R59c`） | ✅ 三个插桩点全部识别 |
| 表生成 `v7_isa.py gen` | ✅ 1480 字节加密表，`v7_isa_key.h` 相对定位正确解析 |
| 隔离包内 `isa_itest.py` | ✅ **6 PASS / 0 FAIL** |

→ **mksh 线的插桩 + 编译 + 验证链路可打包为 8 文件的最小分发包**
（不含 mksh 源码本身，源码由用户自行 clone）。

> **插桩器与源树分离**：`isa_hook.py --srcdir` 接受**任意路径**的源码树，
> 所以分发包不需要自带 `mksh-src/`。用户 `git clone` 后指过去即可。

### 8.3 分发清单校验命令

在干净副本上跑，任何 `FileNotFoundError` / `No such file` 都说明该文件**必须进分发包**：

```bash
# ① 复制待分发内容到隔离位置
rm -rf /tmp/distcheck && mkdir -p /tmp/distcheck/mksh-line/{v7/bash_poc,v7/mksh_poc,tools,v6}
cd <仓库根>
cp v7/bash_poc/{isa_hook.py,anchors.py,isa_hook.c,crypto_isa.h,v7_isa_syms.h,v7_isa_key.h,v7_embed.py} \
   /tmp/distcheck/mksh-line/v7/bash_poc/
cp v7/mksh_poc/{v7mksh_build.sh,v7core_mksh.c,v7_builtin_takeover_mksh.c,v7_shf_inject_mksh.c} \
   /tmp/distcheck/mksh-line/v7/mksh_poc/
cp tools/v7_isa.py /tmp/distcheck/mksh-line/tools/
cp v6/shell_script_obfuscator_v6.sh /tmp/distcheck/mksh-line/v6/

# ② 在隔离目录里跑完整链路
cd /tmp/distcheck/mksh-line
python3 v7/bash_poc/isa_hook.py --interp mksh-R59c --srcdir <你的mksh源码树> --dry-run
python3 tools/v7_isa.py gen --seed 42 -o /tmp/dc.bin --json /tmp/dc.json
```

> ⚠️ **注意 `v7_isa_key.h` 是配对的**：表与解释器必须**配套**。换密钥会让既有表作废、
> 已构建的 mksh 也认不出新表。分发时它必须与 `isa_hook.c` 同一批。

### 8.4 完整分发清单

mksh 线现在**打包能力已通**，完整清单（不含 mksh 源码本身，源码由用户自行 clone）：

| 归属 | 文件 |
|---|---|
| `v7/mksh_poc/` | `v7mksh_build.sh`、`v7core_mksh.c`、`v7_builtin_takeover_mksh.c`、`v7_shf_inject_mksh.c` |
| `v7/bash_poc/`（两线共用的共享工具） | `isa_hook.py`、`anchors.py`、`isa_hook.c`、`crypto_isa.h`、`v7_isa_syms.h`、`v7_isa_key.h`、`v7_embed.py` |
| `v7/` | `v7_build.sh`（统一入口，可选但推荐） |
| `tools/` | `v7_isa.py`、`v6_lint.py`、`argv_leak_scan.py`（构建前检查） |
| `v6/` | `shell_script_obfuscator_v6.sh` |
| 测试用（可选） | `tools/isa_itest.py` |

> `v7_harden.c` / `v7/crypto_core.h` 目前**不属于** mksh 线清单 ——
> mksh 线的密码学走 `crypto_isa.h`（`v7core_mksh.c` include 的就是它）。

---

## 九、当前进度与后续

| 步 | 内容 | 状态 | 提交 |
|---|---|---|---|
| — | ISA 四层插桩（L1/L2/L3/L4）实装 | ✅ 完成 | — |
| — | 锚点表 `MKSH_R59C`（6 op，含 C1/C2 挂载点） | ✅ 完成 | — |
| C1 | 初始化挂载 + builtin 接管（`main.c` builtin 循环后） | ✅ 完成 | `3829537` |
| C2 | `shf_open()` 骨架注入层（打开层劫持） | ✅ 完成 | `2c1098a` |
| C3 | 接入 `v7_build.sh` mksh 线开关（**一条命令出产物**） | ✅ 完成 | `babf886` |
| C4 | 端到端 + 与 bash 线逐字节对拍 + `V7_WRAP` 接入 | 待做 | — |

**C2 的额外价值（已验证）**：在 `shf_open()`（**打开层**）劫持而非"读取层"，
**顺带绕开了 elf 线的 pipe 短读阻塞项** —— mksh 从一个**完整解密好的 memfd**
读取，而非从慢速 pipe 流式读取。详见 §六.4 与
[`BUILD_PER_SHELL.md`](BUILD_PER_SHELL.md) §10.2 / §10.3。

**C3 的验收结果**（10 项全过）：一条命令 rc=0；`[1/3]` 构建出的改版 mksh 与 C2
手工产物 **`cmp` 逐字节一致**（347888 B）；字节账目自洽
（`403238 − 347888 = 55350 = 骨架 + 812`，尾部 `len` 字段独立读出亦为 55350）；
磁盘无明文；篡改 rc=114；不带表令牌漏出；C2 回归（`test_isa_hook_table.sh`
**PASS=18 FAIL=0**）；六类错误路径全部响亮失败；现有套件零回归。

> ⚠️ **上述验收矩阵里的运行验证走的是「无内层口令档」**。
> 2026-09 文档追平期间的复验**新发现了内层口令档的 `read -p` 问题**（§6.3）——
> 它不在上面这张矩阵的覆盖范围内。这正是"验收矩阵要按**档位组合**而不是
> 单个样例来设计"的教训：**10 项全过 ≠ 所有档位都过**。

### 尚未做 / 已知遗留

| 项 | 说明 |
|---|---|
| **内层口令档（`V7_PASS`）不可用** | `read -p` 语义冲突（§6.3 / §6.3b 第 6 项）。**暂用无内层口令档**；修复方向：V6 生成器侧对目标解释器消歧 |
| **跨架构（aarch64）实测** | 本次仅 x86_64 同架构验证。代码路径已就位（含 qemu 缺失时的响亮失败），但**未实测** |
| **`V7_WRAP` 自释放包装** | 尚未接入 mksh 线（属 C4） |
| **与 bash 线产物逐字节对拍** | 两条线产物形态不同（不同解释器），对拍应在**运行输出**层面做（属 C4） |

---

## 十、相关文档

| 想了解 | 读 |
|---|---|
| bash 线怎么构建 | [`BUILD.md`](BUILD.md) |
| 三条产物线怎么选、C 层怎么挂到不同解释器 | [`BUILD_PER_SHELL.md`](BUILD_PER_SHELL.md) |
| mksh 兼容性的实测数据与四大真凶 | [`SHELL_TARGETS.md`](SHELL_TARGETS.md) |
| 踩过的坑（按症状索引） | [`PITFALLS.md`](PITFALLS.md) |
| 令牌化四层表的设计 | [`TOKENIZATION.md`](TOKENIZATION.md) |
