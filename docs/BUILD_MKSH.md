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
| L6 字符串字面量令牌化 | ✅ | ❌ **未移植** |
| C 层三件套（骨架密文注入 / v7core / builtin 接管） | ✅ | ❌ **未移植** |
| **可作为"魔改解释器"打包受保护脚本** | ✅ | ❌ **暂不能** |

> **一句话**：mksh 线目前有**解释器插桩能力**，但还没有**打包保护能力**。
> 也就是说，本文下面的流程能让你构建出一个**已插桩的 mksh**，
> 但它还不能像 bash 线那样把你的脚本加密内嵌进去。

补齐工作（路线 C：C1-C4）的计划与挂载点勘察见
[`BUILD_PER_SHELL.md`](BUILD_PER_SHELL.md) §十。**如果你现在就要能用的保护**，
走 bash 线（[`BUILD.md`](BUILD.md)）或纯脚本线（V6 混淆器，无需任何 C 层构建）。

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

与 bash 线不同：**mksh 线不需要 openssl、不需要 autoconf**。`Build.sh` 是自带的轻量构建脚本。

---

## 四、构建流程（三步）

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

### 步骤 3：编译

```bash
cd mksh-src
TARGET_OS=Linux sh Build.sh -r        # Linux 宿主
# TARGET_OS=Android sh Build.sh -r    # 交叉/真机（需对应 NDK 工具链）

# 产物
ls -la mksh
```

**实测基线**（x86_64 / gcc 13.3）：编译一次通过，产物 **338256 字节**。

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

---

## 六、能力边界与排障

### 6.1 当前边界（诚实版）

| 现象 | 原因 | 状态 |
|---|---|---|
| 无法用 mksh 打包受保护脚本 | C 层三件套未移植 | 路线 C 计划中 |
| `L6` 字符串令牌不解密 | L6 出口挂在 builtin 接管上，随三件套一起缺 | 同上 |
| elf 线 + 内嵌 mksh 静默无输出 | pipe 短读语义不兼容 | 已定位，见 [`BUILD_PER_SHELL.md`](BUILD_PER_SHELL.md) §10.3 |

### 6.2 排障速查

| 症状 | 先查 |
|---|---|
| `错误：<op> 锚点不匹配（mksh 源码结构已变？）` | 源码版本不是 **R59c**（§四 步骤 1） |
| 插桩后编译报未声明符号 | `isa_hook.c` 未随源码树分发（见 §八 自包含性） |
| ISA 测试全 FAIL，无命中 | 表 bin 与 json **不同源** —— 改表后忘同步重导 bin |
| 产物在 mksh 下与 bash 输出不一致 | 跑 `sh tools/sh_compat_check.sh <产物.sh> [原脚本]` |

### 6.3 已知的 mksh 语义陷阱（生成器侧已处理，但改产物时会撞上）

| 构造 | bash | mksh |
|---|---|---|
| `$_` | 上一条命令的最后一个参数 | **恒为 shell 自身路径** |
| `$RANDOM` | Park-Miller | 不同序列 |
| `$-` | 含 `h`/`B` 等标志位 | 不同标志集 |
| `read -a` | 数组 | 语义不同 |
| `shift` 无参数且位置参数为空 | 语句非零、脚本继续 | **当场终止脚本，rc=1** |

> **最后一条踩过一次真雷**：V7 骨架第一行的 `[ -n "$V7_SELF" ] && shift`
> 在"无用户参数"时让 mksh **当场静默退出**，症状与"解密失败/完整性拒绝"
> **完全无法区分**（都是静默 rc）。已加 `[ "$#" -gt 0 ]` 守卫。
> 这类"跨解释器语义分叉伪装成加密故障"的坑，见 [`PITFALLS.md`](PITFALLS.md)。

---

## 七、换版本 / 加插桩点

**加一个新解释器 = 往 `v7/bash_poc/anchors.py` 填一组 `ANCHOR_SET`**，不用改 `isa_hook.py`。

```bash
python3 v7/bash_poc/isa_hook.py --list          # 列出全部锚点集
```

mksh 锚点集（`MKSH_R59C`）的三个插桩点及其**两条硬约束**（源码考古结论，改前必读）
见 [`BUILD_PER_SHELL.md`](BUILD_PER_SHELL.md) §4.2.1。

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
rm -rf /tmp/distcheck && mkdir -p /tmp/distcheck/mksh-line/{v7/bash_poc,tools}
cd <仓库根>
cp v7/bash_poc/{isa_hook.py,anchors.py,isa_hook.c,crypto_isa.h,v7_isa_syms.h,v7_isa_key.h} \
   /tmp/distcheck/mksh-line/v7/bash_poc/
cp tools/{v7_isa.py,isa_itest.py} /tmp/distcheck/mksh-line/tools/

# ② 在隔离目录里跑完整链路
cd /tmp/distcheck/mksh-line
python3 v7/bash_poc/isa_hook.py --interp mksh-R59c --srcdir <你的mksh源码树> --dry-run
python3 tools/v7_isa.py gen --seed 42 -o /tmp/dc.bin --json /tmp/dc.json
python3 tools/isa_itest.py --bash <你的mksh二进制> --table /tmp/dc.bin --json /tmp/dc.json
```

> ⚠️ **注意 `v7_isa_key.h` 是配对的**：表与解释器必须**配套**。换密钥会让既有表作废、
> 已构建的 mksh 也认不出新表。分发时它必须与 `isa_hook.c` 同一批。

### 8.4 尚不自包含的部分

mksh 线**打包能力**（C1-C4，未实现）落地后，还需补入：
`v7_builtin_takeover.c`、`v7core.c`、`v7_harden.c`、`v7/crypto_core.h`，
以及 `v7_build.sh` 的 mksh 分支与 `v6/shell_script_obfuscator_v6.sh`。

---

## 九、当前进度与后续

| 步 | 内容 | 状态 |
|---|---|---|
| — | ISA 四层插桩（L1/L2/L3/L4）实装 | ✅ 完成 |
| — | 锚点表 `MKSH_R59C` | ✅ 完成 |
| C1 | 初始化挂载 + builtin 接管（`main.c` builtin 循环后） | 待做 |
| C2 | `shf_open()` 骨架注入层 | 待做 |
| C3 | 接入 `v7_build.sh` mksh 线开关 | 待做 |
| C4 | 端到端 + 与 bash 线逐字节对拍 | 待做 |

**C2 的额外价值**：在 `shf_open()`（**打开层**）劫持而非"读取层"，
可能**顺带绕开 elf 线的 pipe 短读阻塞项** —— 因为 mksh 将从
一个**完整解密好的 memfd** 读取，而非从慢速 pipe 流式读取。
详见 [`BUILD_PER_SHELL.md`](BUILD_PER_SHELL.md) §10.2 / §10.3。

---

## 十、相关文档

| 想了解 | 读 |
|---|---|
| bash 线怎么构建 | [`BUILD.md`](BUILD.md) |
| 三条产物线怎么选、C 层怎么挂到不同解释器 | [`BUILD_PER_SHELL.md`](BUILD_PER_SHELL.md) |
| mksh 兼容性的实测数据与四大真凶 | [`SHELL_TARGETS.md`](SHELL_TARGETS.md) |
| 踩过的坑（按症状索引） | [`PITFALLS.md`](PITFALLS.md) |
| 令牌化四层表的设计 | [`TOKENIZATION.md`](TOKENIZATION.md) |
