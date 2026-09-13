# 令牌化（V7-ISA）：让产物在磁盘上只是一串随机令牌

> **核心思想**：编译型语言链接后符号仍有结构，而解释器语言可以把**全部语义单元**（不只是一两个函数名）换成令牌——粒度到**每一个命令、每一个字符串**。
>
> 这是解释器语言**独有的最大优势**。

---

## 一、为什么令牌化能成立

```
攻击者的还原路径：
  拿到产物 → 读出"命令名/关键字/变量名" → 理解逻辑

令牌化后：
  产物里只有  xk7a2f  （随机别名）
  真名存在 C 层符号表里（被 VMP 保护）
  → 攻击者拿到的是"没有语义的令牌序列"
```

**关键**：真正的名字**不在产物里**，而在**被保护的 C 层**。

---

## 二、四层表

| 层 | 内容 | 数量 | 插桩点 |
|---|---|---|---|
| **L1** | 内建命令（`echo`/`cd`/...） | 8 | `execute_simple_command` |
| **L2** | 外部命令（`ls`/`cat`/...） | 9 | 同上 |
| **L3** | 关键字（`if`/`for`/`while`/`case`/...） | **13** | `CHECK_FOR_RESERVED_WORD` **宏** |
| **L4** | 变量 + 路径 | 13 + 5 | `variables.c` / 路径 hook |
| **L6** | 字符串字面量 | — | 密文驻留（`orig_ct` + `orig_off`） |

### 2.1 `in` 为什么不表化

bison 的 `for`/`case` 产生式对 `IN` token 位置**深层耦合**，宏还原必炸 `syntax error near unexpected token 'in'`。

**且孤立 `in` 不构成语义指纹**——收益低，风险高，不值。

### 2.2 ★ L3 的头号坑：插桩点打在死代码上

```
错误：find_reserved_word
  → 它是【旁路死代码】（无调用者）
  → L3 全程不生效
  → 且【静默失败】（看起来生效了）

正确：CHECK_FOR_RESERVED_WORD 宏体首行
  → 这才是词法主路径
```

**识破方式**：stderr 里的 `alias not found`。

**通用教训**：**插桩点必须选在主执行路径。验证方式：patch 点后打探针，探针必须真命中。**

---

## 三、令牌化四个技术点

### 3.1 真名不进表（符号 ID 化）

```c
struct isa_entry {
    int  layer;
    char alias[64];      // 别名（产物里出现的就是它）
    int  sym;            // ★ 只存符号 ID，不存真名
    char orig_ct[512];   // 真名密文（L6）
    int  orig_len;
    int  orig_off;
};
```

**为什么**：表里如果同时有 `{alias, orig}`，**内存中就出现了明文配对**——攻击者 dump 内存直接拿到映射表。

### 3.2 密文驻留

真名以**密文**形式存（`orig_ct` + `orig_off`），运行时**按需解密**。

**r28 的进一步强化**：`isa_dec_at` **逐字段按需解密到栈上**，**根本不产生整段明文**。

### 3.3 混合串子串扫描

**问题**：别名可能出现在**更大的字符串内部**（如路径 `/data/xk7a2f/bin`）。

**解法**（`v7_isa_param_scan`）：
1. 形态预检（快速排除不可能的串）
2. 精确查表
3. 容量 fail-safe

### 3.4 词边界锚定

**血案**：裸 `strstr` 导致 `sha512` 里的 `f054` 被误改成 `/data`。

**解法**：词首锚定 + **右边界校验**。

**注意**：`v7_isa_path_step` 被拆成独立函数，是因为 **VMPacker 对 >200B 函数的翻译会出错**。

---

## 四、★ 所有权契约（三次迭代）

**这是 V7-ISA 最难的部分。**

```c
/* v1  返回 static 表指针 */
return isa_table[i].alias;
/* → bash 词法器 FREE(token) 释放非堆地址 → 堆损坏 */

/* v2  返回 strdup 堆拷贝 */
return strdup(isa_table[i].alias);
/* → 把【文件作用域 static 的 token】指向 malloc 小块
     parse_matched_pair 递归回词法器时内层也会改它
     外层回来炸 */

/* v3  只返回【视图】，不接管所有权  ✅ */
const char *view = v7_isa_translate_kw(...);
/* 由宏负责：
     RESIZE_MALLOCED_BUFFER  →  扩容
     strcpy                  →  拷回
     同步 token_index         →  保持一致
*/
```

### 为什么 v2 也不行

v2 的 `strdup` 看似安全（返回堆内存，`FREE` 合法），但它把**文件作用域 static 的 `token` 指针**指向了一块小的 malloc 内存——而 `token` 这个变量是**被递归复用的**（`parse_matched_pair` 递归回词法器时内层也会改写它）。

**中途还试过"只同步长度"**——没用。因为 `sd6o`→`while` 变长只是**第一个坑的引爆条件**，与所有权无关。

> **通用教训**：hook「替换字符串」前先问**指针归谁**、后续会不会被 `realloc`/`free`。
> **改内容安全，换 owner 是把炸弹埋到下游几十行之外。**

---

## 五、四个插桩点

| 文件 | 位置 | 作用 |
|---|---|---|
| `execute_cmd.c` | `lastarg = NULL;` 之后、`find_special_builtin` 之前 | L1/L2 命令名（**单点覆盖**全部分派路径） |
| `y.tab.c` | `CHECK_FOR_RESERVED_WORD` 宏体**首行** | L3 关键字 |
| `variables.c` | `find_variable` 查表前 | L4 变量 |
| `shell.c` | `shell_initialize()` 之后 | 接管安装点 |

### 5.1 ★ L3 与 L4 的区别（易错）

| | L3 关键字 | L4 变量 |
|---|---|---|
| hook 点 | **宏**（不是函数！） | 函数 |
| 原因 | `find_reserved_word` 是死代码 | `find_variable` 在主路径 |

### 5.2 ⚠️ L4 位置参数的坑

```bash
# bash 的 $N 走 param_expand 的 case '0'..'9'
# → 直接取 dollar_vars[]，【不经 find_variable】
# → hook 恒无效，且【静默取空值】（比报错更危险）

正确 hook 点：param_expand 的 switch 【之前】
```

---

## 六、接管输出 builtin

```c
/* shell_builtins[].function 是【运行期可写函数指针】 */
shell_builtins[echo_builtin].function = v7_echo_builtin;
```

**用途**：`echo` 的输出是我们**可控的明文产生点**（可做 L6 字符串还原等）。

---

## 七、懒初始化

**问题**：`v7_isa_init` 初版挂在 `v7_init` 下 → 被 `V7_SELF` 门控 → **裸 bash 永不装载**。

**解法**：**懒初始化**（`isa_tried` 哨兵，**首次翻译时装载**）——与 blob 流程解耦。

```c
if (!isa_tried) { isa_tried = 1; isa_load(); }
```

---

## 八、与 V6 骨架的对接

```
V6 产物（加密的 shell 脚本）
    ↓  挂到魔改 bash 上
魔改 bash 读脚本时：
    1. 从自身尾部读 blob（zread 层）  ← V7 解密
    2. 解密后得到 V6 骨架
    3. 骨架执行时，bash 分派器看到别名 → ISA 翻译 → 真名
```

**无表时** → 空转，**行为与未魔改 bash 完全一致**（设计约束）。

这是关键设计：**魔改层必须"透明"**——没有表时不能有任何行为差异。

---

## 九、调试开关剥离（最值得抄的一节）

**这是"绕过你所有加密"的后门**，必须优先处理。

| 开关 | 通道 | 后果 |
|---|---|---|
| `xtrace` | `print_cmd.c` 的 7 个 `xtrace_print_*` | `set -x` 直接打印明文命令 |
| `verbose` | `y.tab.c`/`make_cmd.c` 回显 | `SHELLOPTS=verbose` 整篇倾倒原文 |
| `BASH_ENV` | `shell.c` | 启动时 source 攻击者的脚本 |
| `PS4` | — | 可注入命令 |
| `BASH_XTRACEFD` | — | 把 trace 重定向到文件 |

### ★ patch 方向的坑

```
禁用型（包整段）      →  #ifdef   ✅
注入 return 型        →  #ifndef  ✅

初版方向用反 → EVIL 仍被 source
```

### 跨语言对照

| 语言 | 对应 bash 的 `BASH_ENV` |
|---|---|
| Python | `sitecustomize.py` / `PYTHONSTARTUP` |
| Lua | `LUA_INIT` |
| PHP | `auto_prepend_file` |
| Node.js | `NODE_OPTIONS=--require` |

**第一优先级**：**先把这些官方开关全部关掉**——它们绕过你所有的加密。

---

## 十、跨语言落地清单

> **通用 vs 不通用**：

| ✅ 通用 | 🔴 不通用 |
|---|---|
| **调试开关清单 + 全部关掉** | **插桩点**（每个语言重找） |
| 载荷追加尾部 + 定长尾读 | **单点分派覆盖**（bash 的结构红利） |
| 令牌化**四个技术点** | 接管输出 builtin（需运行期可写符号表） |
| **所有权契约的教训** | |
| 无表空转（透明性） | |

### 各语言的插桩点线索

| 语言 | 注入点 |
|---|---|
| bash | `zread` 层（读脚本处） |
| Python | `Py_RunMain` 前 |
| Lua | `pmain` 里 `luaL_loadfile` 前 |
| PHP | `php_execute_script` 前 |

---

## 十一、验证

**三条硬判据**（`tools/isa_itest.py`）：

1. 输出与 `/bin/bash` **逐字节一致**
2. **必须真命中别名**（不能"看起来生效"）
3. **必须覆盖变长别名**（`sd6o`→`while`）

**还要做反向验证**：改回旧形态后测试**必须 FAIL**（证明测试有区分力）。

> **血案**：`selftest` 最后一关是 `bash -n` —— 而 `-n` 走**宿主 bash**，**压根不经过 C hook**。于是"改写产物长得对"和"产物能跑"被当成了同一件事。
>
> **改用真二进制 × 真表执行。**
