# 有没有办法「一次写、到处插」？—— 通用 hook 点的结构与边界

> **你的问题**：*"那你还得逐 shell 分析啊，有没有什么办法自建通用 hook 点之类的"*
>
> **结论先行**：
>
> 1. **有一条真实存在的通用路线，而且我找到了证据** —— 不同 shell 的同类逻辑
>    **在结构上高度同构**，只是"函数名、表名、文件位置"不同。这类差异**可以靠
>    "语义锚点 + 多候选探测"自动化**，不必逐 shell 手写。
> 2. **但通用不了的是"语义等价判断"** —— 你得先知道"这个位置等于那个位置"，
>    这需要人（或人写的模板）来判断。**能做的是把这个判断一次性沉淀成规则**。
> 3. 因此正确的目标不是"零人工加 shell"，而是**"人工只判断一次，之后自动适配"**。

---

## 一、先看实证：三个 shell 的同类逻辑长什么样

这是本方案的事实基础。我把 bash / mksh / dash 的 **L3 保留字识别** 摊开并列：

### dash（`parser.c`）

```c
/* 725 行：词法主循环里 */
if (kwd & CHKKWD) {
    const char *const *pp;
    if ((pp = findkwd(wordtext))) {                    /* ← 钩子在这 */
        lasttoken = t = pp - parsekwd + KWDOFFSET;
        goto out;
    }
}

/* 1629 行：查找实现 */
const char *const *findkwd(const char *s)
{
    return findstring(s, parsekwd, sizeof(parsekwd)/sizeof(const char *));
}
```

### mksh（`lex.c`）

```c
/* 1046 行 */
if ((cf & KEYWORD) && (p = ktsearch(&keywords, ident, h)) &&   /* ← 钩子在这 */
    (!(cf & ESACONLY) || p->val.i == ESAC ||
     (unsigned int)p->val.i == ORD(/*{*/ '}'))) {
        afree(yylval.cp, ATEMP);
        return (p->val.i);
}
```

### bash（`y.tab.c`）

```c
/* 5296 行：宏体（真正的词法主路径） */
#define CHECK_FOR_RESERVED_WORD(tok) \
  do { \
    { \
      const char *v7kw = v7_isa_translate_kw (tok); \   /* ← 已插入的钩子 */
      ...
    } \
    for (i = 0; word_token_alist[i].word != NULL; i++) \
      if (STREQ (tok, word_token_alist[i].word)) ...
```

### 抽出同构骨架

| 抽象角色 | dash | mksh | bash |
|---|---|---|---|
| **① 词法产出"当前词"** | `wordtext` | `ident` | `token` |
| **② 一个"查关键字表"的函数** | `findkwd(s)` | `ktsearch(&keywords, s, h)` | `find_reserved_word(s)`（**死代码**）/ 宏 |
| **③ 表本体** | `parsekwd[]` | `keywords`（运行期哈希表） | `word_token_alist[]` |
| **④ 触发点** | `readtoken()` 内 `if(kwd & CHKKWD)` | `lex.c` `if(cf & KEYWORD)` | `read_token_word()` 内宏展开两处 |

> **四个 shell（含 bash）里，③ 全都是一个"字符串 → token"的映射表，
> ② 全都是"给定串、返回对应项"的查表函数。**
> **这个同构性就是通用 hook 的立足点。**

---

## 二、为什么这能被自动化 —— 三条可程序化的识别规则

逐 shell 手写锚点，本质是在回答"**② 在哪、叫什么**"。而这件事**可以用规则自动搜出来**：

### 规则 1：按"表的数据形态"找表（找 ③）

每个 shell 的关键字表都是**一组包含 shell 保留字的字符串数组**。可以直接搜：

```python
RESERVED_WORDS = {"if","then","else","elif","fi","case","esac",
                  "for","while","until","do","done","select","function","{"}

def find_keyword_tables(c_sources):
    """找候选表：一个数组初始化列表，其字符串成员与保留字集合重叠度高"""
    hits = []
    for path, text in c_sources:
        for m in re.finditer(r'\b(\w+)\s*\[\s*\]\s*=\s*\{', text):
            name = m.group(1)
            body = extract_braces(text, m.end() - 1)
            strs = set(re.findall(r'"([^"]+)"', body))
            overlap = strs & RESERVED_WORDS
            if len(overlap) >= 4:          # 至少 4 个保留字命中
                hits.append((path, name, sorted(overlap)))
    return hits
```

**✅ 实测验证（原型已跑通，非推演）**：

| shell | 扫描目标 | 自动找到的表 | 命中保留字 |
|---|---|---|---|
| bash | `bash-5.2/*.c` | `word_token_alist`（`y.tab.c`） | **19 个** |
| mksh | `mksh-R59c/*.c` | `tokentab`（`syn.c`） | **14 个** |
| dash | `dash-0.5.12/src/*.{c,h}` | `parsekwd`（`token_vars.h`） | **16 个** |

> **三个 shell 全部自动命中。**

#### ⚠️ 原型踩到的两个实现坑（必须写进正式实现）

**坑 1：净化必须"等长"，否则偏移全乱**

第一版原型先剥注释/字符串、再在净化文本上定位、却用净化后的偏移去原文取字符串
—— 因为 `"..."` → `""` **改变了长度**，偏移错位，结果 mksh 的 `tokentab`
**明明匹配上了却取不到内容**（表现为"一个都没找到"）。

```python
def blank(m):
    """等长替换：保留换行，其余字符变空格 ⇒ 偏移与原文一一对应"""
    return ''.join('\n' if ch == '\n' else ' ' for ch in m.group(0))

def sanitize(t):
    for pat in (r'/\*.*?\*/', r'//[^\n]*',
                r'"(?:\\.|[^"\\\n])*"', r"'(?:\\.|[^'\\\n])*'"):
        t = re.sub(pat, blank, t, flags=re.S)
    return t
```

**坑 2：花括号配平必须先剥字符串字面量**

mksh 的表项形如 `{ "if", IF, true }` —— 里面的 `"{"`、`"}"` 等字符串
（保留字表本身就含 `"{"`）会让朴素的 `{}` 计数**永不配平**，
body 会一路吃到函数末尾（实测吃了 8580 字符）。**必须先净化再配平。**

**坑 3（最重要）：必须扫"构建后"的树，不能只扫 pristine 源码**

dash 的 `parsekwd[]` **不在源码里** —— 它由 `mktokens` 在构建时生成到
`src/token_vars.h`。只扫 pristine 源树会**漏掉 dash**。

| shell | 表在哪 |
|---|---|
| bash | 源码里（`y.tab.c`，但 `y.tab.c` 本身也是 `yacc` 产物） |
| mksh | 源码里（`syn.c`） |
| **dash** | **构建产物**（`src/token_vars.h`，由 `mktokens` 生成） |

> **结论：发现器必须在"已经 configure/构建过一次"的树上运行。**
> 这也解释了为什么 `isa_hook.py` 现在跑在 `$SRC`（已 configure）而非 tarball 上。

### 规则 2：按"表的消费点"找查表函数（找 ②）

找到表之后，反向搜索"谁在引用它"：

```python
def find_lookup_callers(c_sources, table_name):
    """找引用了该表的函数 —— 大概率就是查表入口"""
    callers = set()
    for path, text in c_sources:
        if table_name not in text: continue
        for fn in iter_functions(text):
            if re.search(r'\b%s\b' % re.escape(table_name), fn.body):
                # 排除"定义该表的函数"本身
                if not re.search(r'\b%s\s*\[\s*\]\s*=' % table_name, fn.body):
                    callers.add((path, fn.name))
    return callers
```

实测：

| shell | 表 | 自动找到的引用者 | 是否为正确钩子 |
|---|---|---|---|
| dash | `parsekwd` | `findkwd()` | ✅ **正确**（一次命中） |
| mksh | `tokentab` | `initkeywords()` | ⚠️ 找到的是**灌表**函数，不是查表函数 → 需规则 3 补 |
| bash | `word_token_alist` | `find_reserved_word()`、宏体 | ⚠️ 两者都命中，**需要判别"哪个在主路径"** |

**这说明规则 2 会给出候选集，需要规则 3 来裁决。**

### 规则 3：用"是否在主执行路径"裁决（**这条最关键**）

`PITFALLS.md` §5.1 那条血案的教训 —— bash 的 `find_reserved_word` 是**死代码**，
插上去编译通过但全程不生效。**这个判别不能靠锚点匹配，要靠可执行性**：

```python
def is_on_main_path(func_name, table_name, c_sources, build_dir):
    """判定函数是否真被调用：查静态调用图 + 可选的运行期探针"""

    # ① 静态：该函数是否被任何地方调用？
    callers = grep_call_sites(func_name, c_sources)
    if not callers:
        return False, "无调用者（死代码）"

    # ② 静态：从 main() 可达吗？
    if not reachable_from_main(func_name, c_sources):
        return False, "不在主调用图"

    # ③ 动态兜底（最可靠）：打一个会**可观测地失败**的探针
    #    —— 插桩后编一次、跑一个含关键字的脚本，看探针是否命中。
    return probe_hits(func_name, build_dir), "探针命中"
```

> **bash 的 `find_reserved_word` 会被规则 ② 直接筛掉**（`print_cmd.c` 里只有一处
> 调用，且不在词法主路径上）—— 当年那个坑，**可以自动化避免**。

---

## 三、更激进的路子：**改造"表"而不是"代码"**

上面是在找"往哪个函数插"。还有一条**更稳、更少侵入**的思路：

### 思路：不动 C 代码，改"表的内容"

回想一下 mksh 的 `initkeywords()`：

```c
for (tt = tokentab; tt->name; tt++)
    ktenter(&keywords, tt->name, hash(tt->name));
```

**关键字是"一个字符串 → 一个 token 值"的映射。** 那么 ——

> **如果我们不改词法函数，而是让"表里同时含别名和真名"呢？**

也就是：**在灌表的时候，把 `while` 的别名 `v7p_xxx` 也 `ktenter` 进去，指向同一个 token 值。**

```c
/* 补丁：initkeywords() 末尾追加 */
for (tt = tokentab; tt->name; tt++) {
    if (is_reserved(tt->name)) {
        for (alias in aliases_of(tt->name))     /* 从 ISA 表读别名 */
            ktenter(&keywords, alias, hash(alias))->val.i = tt->val.i;
    }
}
```

| | 改函数（现在的做法） | 改表（这个思路） |
|---|---|---|
| 侵入性 | 要改词法热路径 | **只改初始化函数**，词法完全不动 |
| 风险 | 缓冲区所有权、递归、越界（r16 血案全在这） | **为零** —— 只是往哈希表多插几个键 |
| 通用性 | 要把翻译函数塞进各 shell | 只需找到"灌表循环"，**三个 shell 都有** |
| 局限 | —— | 只在"运行期建表"的 shell 有效（mksh ✅ / dash ❌ 静态数组） |

> **这是个真实的取舍**：mksh/dash 是**编译期静态表**，bash 是**生成期表**，
> mksh 是**运行期表**。所以"改表"这招**只对 mksh 这类有效**。

---

## 四、诚实的边界：三条自动化不了的东西

前面讲了很多"能自动"，这里说清"不能自动"的：

| # | 不能自动的 | 为什么 | 缓解 |
|---|---|---|---|
| **1** | **语义等价判断** | "dash 的 `findkwd` 等于 bash 的宏"——这需要懂两个 shell | **一次判断，沉淀成模板**（写进 `anchors.py` 的"角色映射"） |
| **2** | **L1/L2 命令词翻译点** | 各 shell 的"命令分派"结构差异最大（bash `execute_simple_command` / mksh `comexec` / dash `evaltree`） | 需人工找，但**只需找一次** |
| **3** | **内存契约** | bash 可扩容 buffer vs mksh 定长 `ident` vs dash stackblock | **不可通用**，每个 shell 必须单独验证 |

**第 3 条是真障碍**，也是 mksh 路线的止损点。

---

## 五、落地方案：把"逐 shell 分析"变成"填一张角色映射表"

### 目标形态

```python
# anchors.py 里的"角色"声明（自动发现的产物）
ROLE_MAP = {
  "dash-0.5.12": {
    "kw_word":    ("parser.c", "wordtext"),          # ① 当前词
    "kw_lookup":  ("parser.c", "findkwd"),           # ② 查表函数  ← 自动找到
    "kw_table":   ("parser.c", "parsekwd"),          # ③ 表        ← 自动找到
    "kw_trigger": ("parser.c", "readtoken"),         # ④ 触发点
    "cmd_word":   ("eval.c",   "evaltree"),          # L1（人工）
    "var_lookup": ("var.c",    "lookupvar"),         # L4（人工）
  },
  "mksh-R59c": {
    "kw_word":    ("lex.c",  "ident"),
    "kw_lookup":  ("lex.c",  "ktsearch"),            # ← 自动找到
    "kw_table":   ("syn.c",  "tokentab"),            # ← 自动找到
    "kw_trigger": ("lex.c",  "lex"),                 # ④ 触发点
    "cmd_word":   ("exec.c", "comexec"),
    "var_lookup": ("var.c",  "varsearch"),
  },
}
```

### 实施步骤

| 步 | 内容 | 自动化程度 | 成本 |
|---|---|---|---|
| **G1** | 写"表发现器"（规则 1）：扫源码找候选关键字表 | ✅ 全自动 | 0.5 天 |
| **G2** | 写"查表函数发现器"（规则 2）：反向找引用者 | ✅ 全自动 | 0.5 天 |
| **G3** | 写"主路径裁决器"（规则 3）：静态调用图 + 探针 | ✅ 全自动（探针需编一次） | 1 天 |
| **G4** | 人工核对 + 落地角色映射表 | ⚠️ **半自动**（审查机器给的候选） | 每 shell 0.5 天 |
| **G5** | 把角色映射接进 `anchors.py`，生成实际锚点 | ✅ 自动 | 0.5 天 |

> 总成本 **≈ 3.5 天**（框架） + **每 shell 0.5 天**（审查，而非从零分析）。
>
> 对比现状（纯手工）：每 shell **≈ 6 天**。
> **收益：每加一个 shell 省 ~5.5 天，第 3 个 shell 起开始净赚。**

### 关键设计约束（吸取 B0 的教训）

1. **发现器只产出候选，不直接改代码** —— 人工确认后才写进 `anchors.py`。
   理由：自动插错位置是"编译通过但静默失效"的最难排查故障（`PITFALLS.md` §5.1）。
2. **必须带"主路径探针"** —— 这是唯一能证伪"死代码"的手段，缺了就会重蹈
   `find_reserved_word` 的坑。
3. **发现器输出要可复现** —— 同一份源码跑两次结果必须一致（否则无法回归）。

---

## 六、回到你的问题，直接回答

> **"有没有什么办法自建通用 hook 点之类的？"**

**有，而且比我上一轮说的乐观。** 具体三条：

1. **同构性是真实的**：三个 shell 的 L3 都是「`某函数(当前词) → 查某表`」，
   只是名字不同。**这个结构可自动识别**（第二节三条规则）。
2. **最值钱的是规则 3（主路径裁决）** —— 它能自动避开当年踩的
   `find_reserved_word` 死代码坑。**这是"通用 hook"最硬的收益。**
3. **"改表"是条更稳的旁路**（第三节）：对 mksh 这类运行期建表的 shell，
   可以完全不碰词法热路径，只在初始化时多插几个键 —— **零内存风险**。

**但要说清楚天花板**：

> **自动化能做到"找到候选位置"，做不到"判断语义等价"。**
> 所以最终形态是：**机器找候选 + 人审一次 + 沉淀成表**，
> 而不是"完全无人干预加 shell"。

---

## 七、建议

如果要做，**先做 G1+G2+G3 的"发现器"**，拿 dash 当靶子（无源码依赖、结构最简）。
验收标准很硬：

> **发现器输出的 `kw_lookup` 必须是 `findkwd`，且必须把 bash 的
> `find_reserved_word` 判为"不在主路径"。**

这两条做不到，说明规则不成立，**立即停**。

---

## 八、进展：规则 1/2/3 已实现并验证（2026-09）

> **迁移注记（2026-09）**：发现器已与表驱动插桩引擎一起**抽出为独立子项目
> `sh-hook`**（「sh 通用 hook 点 —— 便捷快速移植不同 sh 解释器的特性」），
> 现已**并入本仓库子目录 [`sh-hook/`](../sh-hook/README.md)**（git subtree，
> 保留其全部提交历史）。下文 `tools/hook_discover/` 路径已由
> `sh-hook/discover_tables.py` 取代；`tests/test_hook_discover.sh` 改为
> 指向该子目录，缺目录时 SKIP。引擎部分出自 `v7/bash_poc/isa_hook.py` 的
> B0 表驱动重构，bash/mksh 锚点集仍留存本仓库 `v7/bash_poc/anchors.py`。

**已落地**：`sh-hook/discover_tables.py` + `tests/test_hook_discover.sh`

```sh
python3 sh-hook/discover_tables.py \
    <bash源码> <mksh源码> <dash源码>

# 实测输出：
--- /tmp/v7test/bash-5.2 (90 个文件) ---
  ✅ y.tab.c          word_token_alist    :4501  命中22: !,[[,]],case,coproc,do,done,elif
--- /tmp/v7test/mksh-mksh-R59c (24 个文件) ---
  ✅ syn.c            tokentab            :789   命中15: !,[[,case,do,done,elif,else,fi
--- /tmp/v7test/dash-0.5.12/src (64 个文件) ---
  ✅ token_vars.h     parsekwd            :69    命中16: !,case,do,done,elif,else,esac,fi
```

**三个 shell 全部自动命中，且带精确行号。**

回归测试 `tests/test_hook_discover.sh`（7 断言）覆盖：

| 断言 | 作用 |
|---|---|
| `bash/mksh/dash 发现 <表名>` | 核心功能 |
| `reproducible` | 同树两次扫描输出一致（可回归） |
| `sanitize-length-preserving` | **净化等长**（否则偏移错乱，见坑 1） |
| `brace-balance-ignores-string-braces` | **字符串里的花括号不得干扰配平**（坑 2） |

### 下一步（未做）

| 步 | 内容 | 状态 |
|---|---|---|
| G1 | 保留字表发现（规则 1） | ✅ 已完成（sh-hook `discover_tables.py`） |
| G2 | 查表函数发现（规则 2） | ✅ **已完成（2026-09，sh-hook `discover_callers.py`）** |
| G3 | 主路径裁决 + 探针（规则 3） | ✅ **已完成（2026-09，sh-hook `probe_path.py`）** |
| G4 | 人工核对 → 角色映射表 | 📋 待做 |
| G5 | 接进 `anchors.py` | 📋 待做 |

**G2 实测摘要**（详见 sh-hook `docs/DESIGN.md` §4.5）：引用图谱四类
（decl/macro/func-ref/caller）+ 容器链自动展开（运行时哈希型）。
三壳与手工分析交叉验证一致：bash 主路径候选 = 宏展开 `read_token_word`
两处（与本仓库当年插桩选择一致，y.tab.c:5288 注释佐证）；mksh 容器链
`tokentab→keywords` → `yylex`(lex.c:1046)；dash `findkwd` 两个调用点。
修正一处旧认知：`find_reserved_word` 是旁路（print_cmd.c:1398 一处调用）
而非纯死代码——主路径裁决仍归 G3。

**G3 实测摘要**（详见 sh-hook `docs/DESIGN.md` §4.6）：自动探针裁决——
候选前插 `write(2,...)` 探针（零头文件依赖）→ 增量构建 → 跑探针脚本 →
收集 `[PROBE]` 命中。§七的验收标准**两条全部达成**：

| 验收标准（§七） | 实测结果 |
|---|---|
| dash 的 `kw_lookup` 必须是 `findkwd` | ✅ `findkwd()@readtoken`（parser.c:725）命中 |
| bash 的 `find_reserved_word` 必须判为"不在主路径" | ✅ 自动拒绝（y.tab.c func-ref + print_cmd.c:1398 旁路均未命中） |

mksh `yylex`(lex.c:1046) 同样命中。**未命中 ≠ 死代码**：裁决依赖探针
脚本覆盖面（dash exec.c:788 处理 `command -V`，默认脚本未构造该形态
而未命中）。探针幂等：tag 粒度 = `(file, owner)` 不含行号，重跑安全。
回归：sh-hook `tests/test_probe.sh` 6 断言全绿（3 自包含 + 3 壳真实树）。

> **G3 是"通用 hook"的核心价值所在** —— 它能自动避开
> `PITFALLS.md` §5.1 那个 `find_reserved_word` 死代码坑。
> G1 只是证明了"能被自动发现"，**还不足以证明"能自动选对插桩点"**。

---

*本文档基于 2026-09 实测。事实来源：`dash-0.5.12/src/parser.c`（`findkwd@1629`、
`parsekwd`、`readtoken@700`）、`mksh-mksh-R59c/{lex.c:1046,syn.c:789/825}`、
`bash-5.2/{y.tab.c:4501/5296/7714, print_cmd.c:1398}`。
规则 1/2/3 的可运行实现见 [`sh-hook/`](../sh-hook/README.md)（`discover_tables.py` /
`discover_callers.py` / `probe_path.py`）。
相关：[`C_LAYER_ROUTE_COMPARE.md`](C_LAYER_ROUTE_COMPARE.md)、[`PITFALLS.md`](PITFALLS.md) §5.1。*
