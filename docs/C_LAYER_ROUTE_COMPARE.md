# C 层两条路线的对比 —— 「移植到 mksh」vs「做通用补丁」

> **结论先行**
>
> 1. 你说的「补丁主要是构建脚本」**只对了一半**，而且对的是**较容易的那一半**。
>    `isa_hook.c` 本身确实零 bash 依赖（实测：**一个 bash 内部符号都不引用**），
>    但真正卡人的不是补丁脚本，而是**「往哪儿插」这件事在 mksh 里根本不存在对应的位置**。
> 2. 但**「移植」比预想的好**：mksh 的保留字表是**运行期哈希表**（`ktsearch(&keywords,…)`），
>    比 bash 那个**编译期生成**的 `word_token_alist` **更好插**。这一项是净利好。
> 3. **真正该投资的方向是「通用补丁」，但它要通用的不是"构建脚本"，是"锚点表"** ——
>    把 `isa_hook.py` 里那 4 个硬编码 bash 源串，抽成"每个解释器一份锚点声明"，
>    外加把 3 处 Makefile 注入抽象成"构建系统适配器"。
> 4. **第一步应该是最小可验证的一步**：给 mksh 做一次"只有一个插桩点"的 PoC
>    （L3 保留字还原，因为它最好插），验证"补丁脚本 + 锚点表"这套抽象成立。

---

## 零、先把两条路线的"问题清单"分清楚

你的原话拆解：

| 你的判断 | 核对结果 |
|---|---|
| 「这两的工作方向应该不同」 | ✅ **完全正确**。一个是**搬代码**（工作量在语义映射），一个是**造工具**（工作量在抽象） |
| 「补丁主要是构建脚本」 | ⚠️ **半对**。构建脚本是**容易**的那半；难的半是**插桩锚点** |
| 「如果通用补丁能做出来肯定更好」 | ✅ **同意，且有实证支撑**（见第四节） |

---

## 一、路线 A：移植到 mksh —— 要解决哪些问题

### A.1 事实基础：`isa_hook.c` 到底依赖 bash 什么？

先说好消息 —— 实测结论（`v7/bash_poc/isa_hook.c`）：

```
$ grep -nE '\b(STREQ|shell_builtins|parse_and_execute|find_variable|execute_simple_command|word_token_alist)\b' isa_hook.c
（除注释外，零命中）

$ grep -n '^#include' isa_hook.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_isa.h"
#include "v7_isa_key.h"
#include "v7_isa_syms.h"
```

> **`isa_hook.c` 对 bash 的依赖度 = 0**。它只依赖标准 C 库 + 三个自带头文件。
> 所有"往 bash 里伸手"的动作，都发生在 `isa_hook.py` 的**文本插桩**里。

这是路线 A 成本可控的根本原因，也是路线 B 可行的根本原因。

### A.2 要解决的 5 个映射问题

`isa_hook.c` 导出 **5 个入口**，逐个看 mksh 有没有对应的挂钩位置：

| # | 入口 | bash 插桩点 | mksh 对应位置 | 难度 |
|---|---|---|---|---|
| **L1/L2** | `v7_isa_translate_cmd` | `execute_cmd.c` → `execute_simple_command()` 内 | `exec.c:162` → `comexec()` 调用前；或 `exec.c:479` `comexec()` 入口 | 🟡 **中** — 需要定"词展开后、分派前"这个时点 |
| **L3** | `v7_isa_translate_kw` | `y.tab.c` → `CHECK_FOR_RESERVED_WORD` **宏** | `lex.c:1046` `ktsearch(&keywords, ident, h)` | 🟢 **易** — 见 A.3，**比 bash 好插** |
| **L4** | `v7_isa_translate_var` | `variables.c` → `find_variable()` 入口 | `var.c:153` `varsearch()` / `var.c:236` `global()` | 🟢 **易** — mksh 有**唯一漏斗** `varsearch()` |
| **L5** | `v7_isa_translate_paths` | 与 L1 同一插桩点（遍历参数词） | 同 L1 | 🟡 **中** — 跟随 L1 |
| **L6** | （builtin 接管） | `shell.c` → `shell_initialize()` 后 | `main.c:308` `ktinit(APERM,&builtins,…)` 之后 | 🟢 **易** |

**注意 L6**：mksh 的 builtin 注册是 `builtin(name, func)` 一行（`main.c:314` 循环里
就是这么注册 52 个内建命令的）。这意味着**接管 builtin 在 mksh 里反而更干净** ——
bash 那边要劫持 `shell_builtins[].function` 指针，mksh 直接 `ktenter(&builtins,…)`
覆盖表项即可。

### A.3 关键发现：mksh 的保留字表**比 bash 好插**

**bash 侧的痛（已记录在 `isa_hook.py` 的注释里）**：

```
# r16 教训：find_reserved_word 是【旁路死代码】（无调用者），词法主路径是
# CHECK_FOR_RESERVED_WORD 宏（read_token 内两处展开，直接遍历 word_token_alist）。
# 初版 patch 到死代码上，L3 看似构建成功实则全程未还原。
```

bash 的保留字识别分散在：`word_token_alist`（**由 `mkbuiltins`/生成器产出的静态数组**）、
`CHECK_FOR_RESERVED_WORD` 宏（**两处展开**）、还有一个形态酷似的**死函数**
`find_reserved_word`。当年就是踩了"插到死代码上、编译通过但全程没生效"的坑。

**mksh 侧**：

```c
/* lex.c:1046 */
if ((cf & KEYWORD) && (p = ktsearch(&keywords, ident, h)) &&
    (!(cf & ESACONLY) || p->val.i == ESAC ||
     (unsigned int)p->val.i == ORD(/*{*/ '}'))) {
	afree(yylval.cp, ATEMP);
	return (p->val.i);
}
```

> **`ktsearch(&keywords, ident, h)` —— 一个函数调用，一处，无宏展开，无死代码孪生。**
>
> 在这里把 `ident` 先翻译一遍（`v7_isa_translate_kw(ident)`），L3 就通了。
> **没有 bash 那套"宏两处展开 + 死代码干扰"的坑。**

这是路线 A 里**唯一一个比 bash 更省事**的插桩点，价值很高 —— 因为 L3 是
ISA 层里**最影响产物语义**的一层（随机名→`if`/`while` 如果还原不了，语法树直接崩）。

### A.4 mksh 侧真正的结构性差异（也是难点）

| 差异 | bash | mksh | 影响 |
|---|---|---|---|
| **保留字表性质** | 静态生成数组 `word_token_alist` | 运行期哈希表 `keywords`，由 `syn.c:825 initkeywords()` 用 `ktinit`+`ktenter` 建 | ✅ mksh 更易插 |
| **变量查找** | `find_variable()`（多入口） | `varsearch()`（唯一漏斗，`var.c:153`），被 `global`/`local`/`typeset` 共用 | ✅ mksh 更易插 |
| **命令分派** | `execute_simple_command()` 单点 | `comexec()` + `execute()` 两层 | 🟡 要选点 |
| **词法结构** | 独立 `read_token_word()` 函数，宏在其内展开 | `lex.c` 一个大函数内联 `ktsearch` | 🟡 插桩点要重新定位 |
| **代码规模** | bash 5.2 约 12 万行 | mksh R59c 约 3.5 万行 | ✅ mksh **小 3.4 倍**，好读 |
| **构建系统** | autoconf + `Makefile` + `builtins/Makefile` + `mkbuiltins` | `Build.sh`（**单文件 shell 脚本**）直接生成 `Rebuild.sh` | ✅ mksh 更易改，见 A.5 |
| **`PARAMS()` 宏 / K&R 风格** | 有 | 无，纯 C99 原型 | 🟡 移植头文件要改 |
| **`sh.h` 依赖** | 插桩代码不 include | `v7test_inject.c` 需 `#include "sh.h"` | 🟡 但那是 builtin 注册需要 |

### A.5 构建脚本层：mksh 这边**确实简单得多**

bash 那边，`build_poc.sh` 要做 **3 处 Makefile 注入 + 2 处 builtins/Makefile 注入**：

```
lib/sh/Makefile      ① OBJECTS 列表挂 4 个 .o
                     ② 4 条编译规则（含 target-specific flags）
Makefile             ③ LIBS 追加 -lpthread -lcrypto
builtins/Makefile    ④ DEFSRC 加 v6openssl.def
                     ⑤ OFILES 加 v6openssl.o   ← 只改 ④ 会 undefined reference
```

而且有个**已知坑**（`BUILD_PER_SHELL.md` §4.4）：`mkbuiltins` 由 `DEFSRC` + `OFILES`
**共同驱动**，只改 `DEFSRC` 会得到 `undefined reference to openssl_builtin`。

mksh 这边，`Build.sh` 只有一处：

```sh
# Build.sh:610-611
SRCS="lalloc.c edit.c eval.c exec.c expr.c funcs.c histrap.c jobs.c"
SRCS="$SRCS lex.c main.c misc.c shf.c syn.c tree.c var.c"

# Build.sh:2749 链接
v "$CC $CFLAGS $LDFLAGS -o $tcfn $lobjs $LIBS $ccpr"
```

> **加一行 `SRCS="$SRCS v7core.c isa_hook.c v7_builtin_takeover.c"`，
> 再加 `LIBS="$LIBS -lpthread -lcrypto"` —— 两行，够了。**
>
> 没有 OBJECTS/规则/DEFSRC/OFILES 四重同步问题，因为 `Build.sh` 是**顺序脚本**，
> 不是 make 的声明式依赖图。

**所以"补丁主要是构建脚本"这个判断，在 mksh 这边的工作量是 2 行。** 它不难，它只是
**不能自动适配** —— 这正是路线 B 要解决的东西。

### A.6 路线 A 还要背的历史包袱

移植不是"搬 5 个函数"就完事，还得处理已在 `PITFALLS.md` / `BUILD_PER_SHELL.md`
记录的**保护面回退**：

| 项 | bash 侧现状 | mksh 侧将退化成 | 性质 |
|---|---|---|---|
| 进程替换 | 用 `<(...)` | 只能 `mktemp` 临时文件 | ⚠️ 明文窗口（`PITFALLS.md`） |
| eval 自省 | `declare -f eval` | 只能 `command -V eval` | ⚠️ 反调试强度下降 |
| 文本插桩 | 宏内 `RESIZE_MALLOCED_BUFFER` 有明确所有权契约 | mksh `ident[]` 是**栈上定长数组**（`IDENT`） | ⚠️ **新风险点**，见下 |

**最后一条值得单独标红**。bash 那版 L3 插桩踩过一个血案（`isa_hook.py` 注释）：

```
#   正解：结果拷回调用方 buffer —— RESIZE 扩容 + strcpy + 同步 token_index
# 【硬约束】两个展开点都在 read_token_word 内 ⇒ 可直接引用 token /
# token_index / token_buffer_size。
```

mksh 这边更棘手：

```c
/* lex.c:1034 —— ident 是栈上定长数组 */
dp = ident;
while ((dp - ident) < IDENT && (c = *sp++) == CHAR)
	*dp++ = *sp++;
...
memset(dp, 0, (ident + IDENT) - dp + 1);
```

`IDENT` 是**编译期定长**（`sh.h` 里定义）。ISA 别名（如 `v7p_a3f9c2d1e8`，14 字符）
**可能比原名长**，塞进去就有**栈溢出风险**。这需要：
- 要么保证构建期生成的别名**长度 ≤ 最短原名**（约束 `v7_isa.py`）
- 要么改成"翻译在 `ktsearch` 的**入参**上做、结果不回写 `ident`"（更安全）

第二方案更符合"不改控制流"的设计哲学，但要验证 `ktsearch` 之后 `ident` 还有没有被用。

### A.7 路线 A 工作量小结

| 工作项 | 成本 | 难度 |
|---|---|---|
| 头文件去 `PARAMS()` / K&R，适配 mksh | 0.5 天 | 🟢 |
| L3 插桩（`lex.c:1046` ktsearch 前） | 0.5 天 | 🟢 最好插 |
| L4 插桩（`var.c:153` varsearch 入口） | 0.5 天 | 🟢 |
| L6 builtin 接管（`main.c:308` 后） | 0.5 天 | 🟢 已有 PoC 底子 |
| L1/L2/L5 插桩（`comexec` 选点 + 参数词遍历） | 1.5 天 | 🟡 最难的选点 |
| 长别名 → `ident[IDENT]` 溢出风险 | 1 天 | 🔴 **必须验证** |
| 构建脚本（2 行）+ 跑通 | 0.5 天 | 🟢 |
| 与 bash 侧产物对拍验证 | 1 天 | 🟡 |
| **合计** | **≈ 6 天** | 悲观 10 天 |

---

## 二、路线 B：通用补丁 —— 要解决哪些问题

### B.1 澄清：通用补丁要通用的**不是构建脚本**

你说"补丁主要是构建脚本"，我核对后认为要**分开看**：

| 层 | bash 侧现状 | 通用化的真正难度 |
|---|---|---|
| **① 构建脚本** | 5 处 sed 硬编码 | 🟢 **低** — 抽象成"构建系统适配器"即可 |
| **② 插桩锚点** | 4 个硬编码 bash 源串 | 🔴 **高** — 这是真难点 |
| **③ 插桩动作** | `_patch(text, old, new)` 字符串替换 | 🟡 **中** — 动作本身可复用，但"替换什么"随 shell 变 |
| **④ C 核心** | `isa_hook.c` / `v7core.c` / `crypto_isa.h` | 🟢 **零成本** — 已验证零 bash 依赖 |

**②才是真瓶颈**。看 `isa_hook.py` 的四个锚点：

```python
EC_DECL_ANCHOR = (
    "static int execute_simple_command "
    "PARAMS((SIMPLE_COM *, int, int, int, struct fd_bitmap *));\n"
)
YT_OLD = (
    "/* Check to see if TOKEN is a reserved word and return the token\n"
    "   value if it is. */\n"
    "#define CHECK_FOR_RESERVED_WORD(tok) \\\n"
    "  do { \\\n"
)
VAR_OLD = (
    "SHELL_VAR *\n"
    "find_variable (name)\n"
    "     const char *name;\n"
    "{\n"
    "  SHELL_VAR *v;\n"
    "  int flags;\n"
    "\n"
)
SC_OLD = (
    "  shell_initialize ();\n"
    "\n"
    "  set_default_lang ();\n"
)
```

> 这 4 个是**逐字符匹配 bash 源码**的。换 mksh 一个都匹配不上 ——
> `execute_simple_command` / `CHECK_FOR_RESERVED_WORD` / `find_variable` / `shell_initialize`
> 在 mksh 里**这四个名字全都不存在**。

### B.2 通用补丁要交付的 4 件事

**① 锚点表（Anchor Table）—— 核心交付物**

把"哪个解释器、往哪儿插、插什么"变成**声明式数据**：

```python
# 伪码：未来的 anchors/<interp>.py
ANCHORS = {
  "bash-5.2": {
    "cmd":      {"file": "execute_cmd.c", "anchor": "static int execute_simple_command ...", "action": "translate_cmd_and_paths"},
    "kw":       {"file": "y.tab.c",       "anchor": "#define CHECK_FOR_RESERVED_WORD(tok) ...", "action": "translate_kw_inplace"},
    "var":      {"file": "variables.c",   "anchor": "SHELL_VAR *\nfind_variable (name)\n ...", "action": "translate_var_prefix"},
    "builtin":  {"file": "shell.c",       "anchor": "  shell_initialize ();\n", "action": "install_takeover_and_harden"},
  },
  "mksh-R59c": {
    "cmd":      {"file": "exec.c",  "anchor": "\treturn (call_builtin(get_builtin...", "action": "translate_cmd_and_paths"},
    "kw":       {"file": "lex.c",   "anchor": "\t\tif ((cf & KEYWORD) && (p = ktsearch(&keywords, ident, h)) &&", "action": "translate_ident_before_lookup"},
    "var":      {"file": "var.c",   "anchor": "\tglobal(const char *n)\n{\n\treturn (isglobal(n, true));\n}", "action": "translate_var_prefix"},
    "builtin":  {"file": "main.c",  "anchor": "\tfor (i = 0; mkshbuiltins[i].name != NULL; ++i) {", "action": "register_extra_builtins"},
  },
}
```

**② 构建系统适配器（Build Adapter）**

```python
# 伪码
ADAPTERS = {
  "autoconf-make": lambda src, objs, libs: [     # bash
      sed("lib/sh/Makefile", OBJECTS_ANCHOR, objs),
      append_compile_rules("lib/sh/Makefile", objs),
      sed("Makefile", LIBS_ANCHOR, libs),
      sed("builtins/Makefile", DEFSRC_ANCHOR),   # ← 注意 OFILES 也要
      sed("builtins/Makefile", OFILES_ANCHOR),
  ],
  "buildsh": lambda src, objs, libs: [           # mksh
      sed("Build.sh", 'SRCS="$SRCS lex.c main.c misc.c shf.c syn.c tree.c var.c"',
                      'SRCS="$SRCS lex.c main.c misc.c shf.c syn.c tree.c var.c $EXTRA"'),
      sed("Build.sh", 'LIBS=', 'LIBS="$LIBS -lpthread -lcrypto"'),
  ],
}
```

**③ 失败要响亮（fail-loud）—— 已有基础，需泛化**

`isa_hook.py` 现在的哲学是对的：

```python
if old not in text:
    sys.stderr.write("错误：%s 锚点不匹配（bash 源码结构已变？）\n" % tag)
    sys.exit(1)
```

泛化后要更狠：**锚点表要带"预期版本/指纹"**，锚点匹配失败时明确说
"这份解释器源码是 bash-5.3，我们只验证过 5.2 —— 请手工核对后更新锚点表"。

**④ 幂等 + 已知形态回滚**

`isa_hook.py` 已经做了（`EC_DECL_EXTRA_V1` / `YT_NEW_V1` / `YT_NEW_V2` 的回滚分支）。
这套机制**与 shell 无关，可直接复用**。

### B.3 通用补丁**做不到**的那部分

诚实地说清边界，避免高估：

| 期望 | 现实 |
|---|---|
| "一套补丁自动适配任何 shell" | ❌ 做不到。锚点表**必须每个 shell 手写**，因为要区分"这个函数在这个 shell 里叫什么、签名如何、前后文长什么样" |
| "自动发现插桩点" | ❌ 高风险。自动 = 解析 C 语法树 = 一条新的研究线，且"插错地方编译通过但行为错"是最难排查的故障（bash 的 `find_reserved_word` 死代码就是活例） |
| "L6 builtin 接管通用" | ⚠️ 半通用。**注册机制**可通用，但**接管哪个 builtin、怎么接管**因 shell 而异（bash 劫持函数指针，mksh 覆盖哈希表项） |
| "内存所有权契约通用" | ❌ 完全不通用。bash 的 `RESIZE_MALLOCED_BUFFER` vs mksh 的 `ident[IDENT]` 定长数组，是**两种完全不同的风险模型** |

> **一句话**：通用补丁能通用的是**「表 + 适配器 + 失败策略 + 幂等」这四件工程件**，
> 不能通用的是**「锚点内容」和「内存契约」这两件语义件**。

### B.4 路线 B 工作量小结

| 工作项 | 成本 | 难度 |
|---|---|---|
| 抽锚点表结构 + 把 bash 现有 4 锚点迁进去（**零行为变化**） | 1 天 | 🟢 |
| 抽构建适配器 + 把 `build_poc.sh` 的 5 处 sed 迁进去（零行为变化） | 1 天 | 🟢 |
| 版本指纹 / 失败策略强化 | 0.5 天 | 🟢 |
| 写 mksh 锚点表（**这一步就会暴露所有"没想清楚"的地方**） | 1.5 天 | 🔴 |
| 回归验证：现有 bash 线**逐字节不变** | 0.5 天 | 🟢 |
| **合计** | **≈ 4.5 天** | |

---

## 三、逐项对比

| 维度 | 路线 A：移植到 mksh | 路线 B：通用补丁 |
|---|---|---|
| **本质** | 搬 5 个入口 + 重定位插桩点 | 造一层抽象，让"插桩"可声明 |
| **先决问题** | mksh 侧内存契约（`ident[IDENT]` 定长） | 锚点表结构设计 |
| **最大风险** | 别名长度 > `IDENT` → 栈溢出 | 抽象做早了 → 为不存在的第二/第三个 shell 造复杂度 |
| **最难一步** | L1/L2/L5 的 `comexec` 选点 | mksh 锚点表（会反过来暴露抽象漏洞） |
| **能否复用已有工作** | `isa_hook.c` 零改动可直接编 | 幂等/回滚机制可直接复用 |
| **构建脚本工作量** | 2 行 | 写一次适配器（≈1 天），之后每 shell 加 2 行 |
| **工作量** | ≈ 6 天（悲观 10） | ≈ 4.5 天（含 mksh 表） |
| **完成后资产** | mksh 能跑 ISA 层 | **bash + mksh 都能插桩，且第三个 shell 是"填表"** |
| **对 bash 线的影响** | 无 | **有**（重构 `isa_hook.py`/`build_poc.sh`），需逐字节回归兜底 |
| **与你判断的差异** | — | 你说"补丁主要是构建脚本" —— **构建脚本是最轻的一层，重的是锚点表** |

**一个不对称优势**：做完路线 B，路线 A 的"重定位插桩点"变成"填一张表"。
反过来做完路线 A，路线 B 还得重做一遍。**所以 B 应该先做。**

---

## 四、哪个更值得深挖 —— 结论与建议

### 4.1 结论

> **两者不是二选一，是「先 B 后 A」。**
>
> - 只做 A：得到"mksh 支持"，代价 ≈6 天，且第三个 shell 要重来一遍。
> - 只做 B：得到"插桩框架"，但不接一个真实新 shell，**抽象是否成立无法证伪**。
> - **做 B 的同时，用 mksh 当"第二个实例"来逼出抽象漏洞** —— 这是唯一能同时验证两件事的路径。

### 4.2 为什么通用补丁"能做出来"是有实证的

不是乐观猜测，有三条硬证据：

1. **`isa_hook.c` 零 bash 依赖**（实测 grep 零命中）—— C 核心层天然通用。
2. **插桩动作已经抽象过一次了**。`_patch(text, old, new, tag, site_old, site_new)`
   本身就是"锚点替换"的通用原语，只是锚点值被写死。
3. **mksh 的两个关键挂钩点比 bash 更干净**：
   - `ktsearch(&keywords, ident, h)`（L3）—— 单点、无宏、无死代码孪生
   - `varsearch()`（L4）—— 唯一漏斗，`global`/`local`/`typeset` 共用
   这**降低了"第二个实例"的成本**，让"用 mksh 逼出抽象"变得可行。

### 4.3 建议的执行顺序（每步都可独立验收）

| 步骤 | 内容 | 验收标准 | 成本 |
|---|---|---|---|
| **B0** | 抽锚点表 + 构建适配器，**bash 线零行为变化** | `regress.sh` 20/20 绿，产物 md5 与重构前**逐字节一致** | 1.5 天 |
| **B1** | 写 mksh 锚点表（只写 L3 一项） | 插桩脚本能对 mksh 源码成功插入一段空转翻译 | 0.5 天 |
| **A1** | mksh L3 真插桩（`lex.c:1046`）+ 编译跑通 | mksh 能跑一个**只有随机保留字**的 V6 产物 | 1 天 |
| **A2** | L4 / L6 插桩（都是易点） | 位置参数 + builtin 接管在 mksh 下生效 | 1 天 |
| **A3** | `ident[IDENT]` 溢出验证（**止损点**） | 别名长度约束写进 `v7_isa.py`；构造最长别名压测不崩 | 1 天 |
| **A4** | L1/L2/L5 插桩（最难） | mksh 能跑完整 V6 产物，与 bash 产物输出对拍一致 | 1.5 天 |

> **止损点设在 A3**。如果 `ident[IDENT]` 的约束无法在不破坏 ISA 随机化的前提下满足，
> **立刻停**，把 B0 的成果（锚点表框架 + bash 线零回归）作为净收益保留。

### 4.4 一句话回答"哪个更值得深挖"

> **深挖「通用补丁」，但不要真空里造抽象 —— 拿 mksh 当第二个实例逼它。
> 顺序是 B0 → B1 → A1…A4，止损点放在 A3（mksh 定长 `ident` 缓冲区）。**
>
> 单看"值不值得"，通用补丁**更值得**：它的产出是**可复用的插桩框架**，
> 而移植的产出只是**一个 shell 的支持**。但通用补丁的复杂度**不能自证**，
> 必须有一个真实的第二目标 —— mksh 恰好是最合适的那个（代码量小 3.4 倍、
> 两个挂钩点比 bash 干净、构建系统是单文件脚本）。

---

## 五、需要你拍板的两个问题

1. **是否接受路线 B 要重构 `isa_hook.py` / `build_poc.sh`？**（有逐字节回归兜底，
   但这是对**已验证可用**的 bash 线动刀 —— 你的 `PITFALLS.md` §8.7.1 那条
   "最小增量二分"的教训在这里同样适用。）
2. **mksh 的目标定位是什么？** 是"产出一个能跑 V6 产物的 mksh"（产品向），
   还是"当通用补丁的第二个实例，验证抽象"（框架向）？**定位不同，A3 止损点的取舍不同。**

---

*本文档基于 2026-09 实测。事实来源：`v7/bash_poc/isa_hook.c`（813 行，零 bash 依赖）、
`v7/bash_poc/isa_hook.py`（296 行，4 个硬编码锚点）、`v7/bash_poc/build_poc.sh`
（5 处 Makefile/builtins Makefile 注入）、`/tmp/v7test/mksh-mksh-R59c/`
（R59c，35227 行：`lex.c:1046`、`var.c:153/236`、`exec.c:479`、`main.c:308`、`Build.sh:610/2749`）。
相关文档：[`BUILD_PER_SHELL.md`](BUILD_PER_SHELL.md)、[`GENERALIZATION_FEASIBILITY.md`](GENERALIZATION_FEASIBILITY.md)、
[`PITFALLS.md`](PITFALLS.md)、[`INTERP_COMPAT_LAYER.md`](INTERP_COMPAT_LAYER.md)。*
