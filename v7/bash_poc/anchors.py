#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
anchors.py —— 插桩锚点表（B0：把「往哪儿插」从代码里搬到数据里）

背景
================================================================================
isa_hook.py 以前把 4 个插桩位置**硬编码**成 bash 源码字符串：

    EC_DECL_ANCHOR = "static int execute_simple_command PARAMS((...))"
    YT_OLD         = "#define CHECK_FOR_RESERVED_WORD(tok) \\\n  do { \\\n"
    VAR_OLD        = "SHELL_VAR *\nfind_variable (name)\n ..."
    SC_OLD         = "  shell_initialize ();\n"

这 4 个串只存在于 bash 源码里。想给别的解释器（mksh/dash/…）插桩，
一个都匹配不上 —— 因为 mksh 里压根没有 `find_variable` 这个函数。

本文件把所有「位置 + 插入内容」抽成**声明式数据**：
  每个解释器一份 ANCHOR_SET，isa_hook.py 只负责读表 + 执行，不含任何 shell 知识。

设计约束（B0 阶段）
================================================================================
1. **零行为变化** —— 对 bash-5.2 的插桩结果必须与重构前**逐字节一致**。
2. **只搬不改** —— 本轮不做任何清理/重命名/格式调整，纯粹把常量挪个地方。
3. **表是纯数据** —— 不允许在表里写逻辑（lambda/条件分支），否则又变回代码。

术语
================================================================================
anchor  —— 「锚点」：一段用于**定位**的源码文本（要求逐字符匹配）。
site    —— 「插桩点」：锚点定位后，实际被替换掉的**更大**文本片段。
           多数情况 anchor == site；只有 execute_cmd.c 两者不同
           （anchor 是声明行，site 是函数体内的执行序起点）。

site 与 anchor 分开，是因为一个文件里要插**两处**（声明区 + 函数体），
而它们的位置不同。旧代码用 `_patch(..., site_old=..., site_new=...)` 表达这件事。
"""

# =============================================================================
# bash 5.2 —— 已在生产验证的锚点集（从 isa_hook.py 原样搬入，一字未改）
# =============================================================================

# ---- execute_cmd.c ----
# 插桩点 1：声明区（在 execute_simple_command 的前置声明行后挂 extern）
EC_DECL_ANCHOR = (
    "static int execute_simple_command "
    "PARAMS((SIMPLE_COM *, int, int, int, struct fd_bitmap *));\n"
)
EC_DECL_EXTRA = (
    "/* r16：V7 ISA 表翻译（v7/bash_poc/isa_hook.c；alias→orig 单点还原） */\n"
    "extern void v7_isa_translate_cmd PARAMS((char **));\n"
    "extern char *v7_isa_translate_paths PARAMS((const char *));\n"
)

# 插桩点 2：函数体内 —— `lastarg = NULL` 之后、首个分派读取之前
# （单点覆盖 builtin/external/function/execve 全部分派路径）
EC_SITE_OLD = (
    "  lastarg = (char *)NULL;\n"
    "\n"
    "  begin_unwind_frame (\"simple-command\");\n"
)
EC_SITE_NEW = (
    "  lastarg = (char *)NULL;\n"
    "\n"
    "  /* r16：V7 ISA 表翻译（alias→orig），须在首个分派读取前完成；\n"
    "     无表时空转（isa_hook.c 设计约束：行为与未魔改 bash 一致）。\n"
    "     r16-5：追加 L4 路径常量还原——遍历全部参数词做子串替换。 */\n"
    "  if (words && words->word)\n"
    "    {\n"
    "      WORD_LIST *wl;\n"
    "\n"
    "      v7_isa_translate_cmd (&words->word->word);\n"
    "      for (wl = words; wl; wl = wl->next)\n"
    "        {\n"
    "          char *np = v7_isa_translate_paths (wl->word->word);\n"
    "          if (np != NULL)\n"
    "            wl->word->word = np;   /* 旧串不 free：WORD_DESC 归 unwind 栈管理 */\n"
    "        }\n"
    "    }\n"
    "\n"
    "  begin_unwind_frame (\"simple-command\");\n"
)

# r16-3 旧形态（历史演进，用于幂等回滚，勿删）
EC_SITE_NEW_V1 = (
    "  lastarg = (char *)NULL;\n"
    "\n"
    "  /* r16：V7 ISA 表翻译（alias→orig），须在首个分派读取前完成；\n"
    "     无表时空转（isa_hook.c 设计约束：行为与未魔改 bash 一致）。 */\n"
    "  if (words && words->word)\n"
    "    v7_isa_translate_cmd (&words->word->word);\n"
    "\n"
    "  begin_unwind_frame (\"simple-command\");\n"
)
EC_DECL_EXTRA_V1 = (
    "/* r16：V7 ISA 表翻译（v7/bash_poc/isa_hook.c；alias→orig 单点还原） */\n"
    "extern void v7_isa_translate_cmd PARAMS((char **));\n"
)

# ---- y.tab.c ----
# r16 教训：find_reserved_word 是【旁路死代码】（无调用者），词法主路径是
# CHECK_FOR_RESERVED_WORD 宏（read_token 内两处展开，直接遍历 word_token_alist）。
# 初版 patch 到死代码上，L3 看似构建成功实则全程未还原。
YT_OLD = (
    "/* Check to see if TOKEN is a reserved word and return the token\n"
    "   value if it is. */\n"
    "#define CHECK_FOR_RESERVED_WORD(tok) \\\n"
    "  do { \\\n"
)
# r16-5 修复（v3）：绝不夺取 token buffer 的所有权。
#   token 是文件作用域 static，且 parse_matched_pair 会递归回词法器：任何
#   「把 tok 指向新 malloc 块」的做法都会让外层的 RESIZE_MALLOCED_BUFFER
#   (token, ..) 去 xrealloc 一个不属于它的 chunk → munmap_chunk(): invalid
#   pointer（只在「递归词法 + 递归内命中别名」的组合下炸，单句探针全绿）。
#   正解：结果拷回调用方 buffer —— RESIZE 扩容 + strcpy + 同步 token_index
#   （长度也必须同步：alias 与 orig 不等长，sd6o→while 是 +1）。
# 【硬约束】两个展开点都在 read_token_word 内 ⇒ 可直接引用 token /
# token_index / token_buffer_size。若未来 bash 把调用点挪出该函数，这里会
# 编译失败或立刻段错误 —— 响亮地失败远好过静默越界。
YT_BODY = "#define CHECK_FOR_RESERVED_WORD(tok) \\\n  do { \\\n"
YT_HEAD = (
    "/* r16：V7 ISA L3 保留字还原（随机名→if/while/...，v7/bash_poc/isa_hook.c）。"
    "主路径是本宏（find_reserved_word 是旁路死代码） */\n"
    "extern const char *v7_isa_translate_kw PARAMS((const char *));\n"
    "\n"
    "/* Check to see if TOKEN is a reserved word and return the token\n"
    "   value if it is. */\n"
)
YT_NEW = YT_HEAD + YT_BODY + (
    "    { \\\n"
    "      const char *v7kw = v7_isa_translate_kw (tok); \\\n"
    "      if (v7kw != (const char *)(tok) && v7kw != (const char *)NULL) \\\n"
    "        { \\\n"
    "          size_t v7l = strlen (v7kw); \\\n"
    "          RESIZE_MALLOCED_BUFFER (tok, token_index, v7l + 1, \\\n"
    "                                  token_buffer_size, TOKEN_DEFAULT_GROW_SIZE); \\\n"
    "          strcpy (tok, v7kw); \\\n"
    "          token_index = v7l; \\\n"
    "        } \\\n"
    "    } \\\n"
)
# 历史形态，按时间倒序回滚用：
#   V2 = r16-3 形态（直接把 tok 换成 strdup 结果：长度越界 + 所有权掠夺）
#   V1 = r16-5 早 probes（换指针 + 同步长度：解了越界，没解所有权）
YT_NEW_V2 = YT_HEAD + YT_BODY + "    tok = (char *)v7_isa_translate_kw (tok); \\\n"
YT_NEW_V1 = YT_HEAD + YT_BODY + (
    "    { \\\n"
    "      const char *v7kw = v7_isa_translate_kw (tok); \\\n"
    "      if (v7kw != (const char *)(tok) && v7kw != (const char *)NULL) \\\n"
    "        { tok = (char *)v7kw; token_index = strlen (tok); } \\\n"
    "    } \\\n"
)

# ---- variables.c（r16-5：L4 位置参数） ----
# 锚点取完整的 K&R 函数头 + 首两行局部变量声明：切勿只匹配 `find_variable (name)`，
# 那会把 extern 插到 "SHELL_VAR *"（返回类型）与函数名之间劈开定义
# （r16 初版在 y.tab.c 上踩过同类坑，症状是几十条 "two or more data types"）。
VAR_OLD = (
    "SHELL_VAR *\n"
    "find_variable (name)\n"
    "     const char *name;\n"
    "{\n"
    "  SHELL_VAR *v;\n"
    "  int flags;\n"
    "\n"
)
VAR_DECL_EXTRA = (
    "/* r16-5：V7 ISA L4 位置参数还原（v7/bash_poc/isa_hook.c） */\n"
    "extern char *v7_isa_translate_var PARAMS((const char *));\n"
)
VAR_NEW = (
    "/* r16-5：V7 ISA L4 位置参数还原（别名变量 → 真实位置参数）。\n"
    "   必须放在任何查找之前；递归查真名安全——真名（\"1\"..\"9\"）不在别名表内。\n"
    "   运行时取值 ⇒ shift 后的漂移天然跟随，无需构建期绑定。 */\n"
    "extern char *v7_isa_translate_var PARAMS((const char *));\n"
    "\n"
    "SHELL_VAR *\n"
    "find_variable (name)\n"
    "     const char *name;\n"
    "{\n"
    "  SHELL_VAR *v;\n"
    "  int flags;\n"
    "\n"
    "  {\n"
    "    char *v7real = v7_isa_translate_var (name);\n"
    "    if (v7real != NULL)\n"
    "      {\n"
    "        SHELL_VAR *v7v = find_variable (v7real);\n"
    "        free (v7real);\n"
    "        if (v7v != NULL)\n"
    "          return v7v;\n"
    "      }\n"
    "  }\n"
    "\n"
)

# ---- shell.c（r27 / ShellVMP T1：自定义 builtin 接管安装点） ----
# 时机要求：必须在 shell_initialize() 之后 —— shell_builtins[] 是运行期全局
# 数组，shell_initialize 才把它和 num_shell_builtins 填好。早于它调用会
# 遍历空数组（不报错但静默失效，属于"以为保护了其实没保护"）。故选此处。
SC_OLD = (
    "  shell_initialize ();\n"
    "\n"
    "  set_default_lang ();\n"
)
SC_NEW = (
    "  shell_initialize ();\n"
    "\n"
    "  /* r27（ShellVMP T1）：自定义 builtin 接管（L6 参数密文令牌）。\n"
    "     劫持 shell_builtins[] 的 function 指针，让 echo 等输出型命令走\n"
    "     我们的 C 实现（参数解密 + 直写 fd + 栈副本即擦）。\n"
    "     fail-closed：无 L6 表时不接管，行为与原生 bash 完全一致。 */\n"
    "  {\n"
    "    extern void v7_builtin_takeover_install (void);\n"
    "    v7_builtin_takeover_install ();\n"
    "  }\n"
    "\n"
    "  /* r29（ShellVMP T2）：抗 dump 加固 —— 必须放在【最后】。\n"
    "     理由：① 此刻自解密 / 读表 / builtin 接管都已完成，密钥与表已在\n"
    "     内存，正是最该保护的时点；② seccomp 一旦装上就不可撤除，若早于\n"
    "     上述动作会自伤（读表要 open/read，自解密要 memfd 等）；\n"
    "     ③ 此后 bash 进入主命令循环，不再需要被 trace / 读内存。\n"
    "     fail-open：失败不中断（纵深保险，非唯一防线）。\n"
    "     V7_NO_HARDEN=1 可关闭（排查用）。 */\n"
    "  {\n"
    "    extern void v7_harden_install (void);\n"
    "    v7_harden_install ();\n"
    "  }\n"
    "\n"
    "  set_default_lang ();\n"
)


# =============================================================================
# 锚点集（Anchor Set）—— isa_hook.py 的可插拔单元
# =============================================================================
#
# 一个 ANCHOR_SET 描述「一个解释器的一整套插桩」。字段含义：
#
#   name      解释器标识（用于报错信息，如 "bash-5.2"）
#   files     文件槽位 → 该解释器里承载该插桩点的**源码文件名**
#   ops       插桩操作的有序列表，每项：
#               file    文件槽位（对应 files 的 key）
#               tag     人类可读标签（报错时显示）
#               kind    "append_after"  —— 在 anchor 之后追加 new
#                       "replace"       —— 把 site_old 替换成 site_new
#               anchor  kind=append_after 时必填：定位串
#               new     append_after 的追加内容 / replace 的新内容
#               site_old/site_new  replace 用
#               rollback 可选：[(old_form, restore_to), ...] 历史形态回滚
#                       执行前若发现 old_form 存在且 new 缺席，先还原成
#                       restore_to（这样幂等检查不会误判"源码结构已变"）。
#
# 注意：表里**只有数据**。任何需要判断/循环的逻辑都留在 isa_hook.py。

BASH_52 = {
    "name": "bash-5.2",
    "files": {
        "cmd": "execute_cmd.c",
        "kw": "y.tab.c",
        "var": "variables.c",
        "shell": "shell.c",
    },
    "ops": [
        # ---- execute_cmd.c：① 声明区 ----
        # 现状：在 execute_simple_command 的前置声明行后追加 extern 声明块。
        # 历史形态（r16-3）只声明了 translate_cmd、缺 translate_paths，需就地升级：
        # 把「anchor + 旧声明块」还原成「anchor」，再走正常追加。
        {
            "file": "cmd",
            "tag": "execute_cmd.c 声明",
            "kind": "append_after",
            "anchor": EC_DECL_ANCHOR,
            "new": EC_DECL_EXTRA,
            "rollback": [
                # r16-3 形态 = anchor + 只有 translate_cmd 的旧声明块
                (EC_DECL_ANCHOR + EC_DECL_EXTRA_V1, EC_DECL_ANCHOR),
            ],
        },
        # ---- execute_cmd.c：② 函数体内 ----
        {
            "file": "cmd",
            "tag": "execute_cmd.c 插桩",
            "kind": "replace",
            "site_old": EC_SITE_OLD,
            "site_new": EC_SITE_NEW,
            # 历史形态回滚：(旧形态, 还原成) —— r16-3 → 回滚到未插桩形态再重插
            "rollback": [
                (EC_SITE_NEW_V1, EC_SITE_OLD),
            ],
        },
        # ---- y.tab.c：保留字（L3） ----
        {
            "file": "kw",
            "tag": "y.tab.c CHECK_FOR_RESERVED_WORD",
            "kind": "replace",
            "site_old": YT_OLD,
            "site_new": YT_NEW,
            "rollback": [
                (YT_NEW_V1, YT_OLD),
                (YT_NEW_V2, YT_OLD),
            ],
        },
        # ---- variables.c：位置参数（L4） ----
        {
            "file": "var",
            "tag": "variables.c find_variable",
            "kind": "replace",
            "site_old": VAR_OLD,
            "site_new": VAR_NEW,
        },
        # ---- shell.c：builtin 接管 + 加固安装点 ----
        {
            "file": "shell",
            "tag": "shell.c builtin 接管安装点",
            "kind": "replace",
            "site_old": SC_OLD,
            "site_new": SC_NEW,
        },
    ],
}

# =============================================================================
# mksh R59c —— B1 试验性锚点集（只做 L3 保留字，验证"填表"这条路走不走得通）
# =============================================================================
#
# 与 bash 的结构差异（这是"通用补丁"要抽象掉的东西）：
#
#   bash：保留字识别在 CHECK_FOR_RESERVED_WORD **宏**里（read_token_word 内两处展开），
#         宏体遍历**编译期生成**的 word_token_alist；旁边还有个形态酷似的
#         **死函数** find_reserved_word（r16 曾误插到这里，编译通过但全程失效）。
#
#   mksh：保留字识别是 lex.c 里**一句** ktsearch(&keywords, ident, h) ——
#         查的是**运行期哈希表** keywords（syn.c:825 initkeywords() 用 ktinit/ktenter 建）。
#         单点、无宏、无死代码孪生 ⇒ 比 bash 好插。
#
# 插桩动作：在 ktsearch 之前把 ident 翻译成真名。
#   ⚠️ 已知风险（B0 阶段先记录、不解决）：mksh 的 ident 是**栈上定长数组**
#   （lex.c:1034 `dp = ident;`，上界是编译期常量 IDENT）。ISA 别名长于原名时
#   会有溢出风险。这正是路线 A 的止损点（见 docs/C_LAYER_ROUTE_COMPARE.md §A.6）。
#   本轮目标只是验证"锚点表能定位并插入"，不追求可运行。
#
# 状态：**试验性**。未接入构建，未验证可运行。仅用于验证锚点表抽象。

MKSH_IDENT_LOOKUP = (
    "\tif (*ident != '\\0' && (cf & (KEYWORD | ALIAS))) {\n"
)

MKSH_KW_HEAD = (
    "/* V7 ISA L3 保留字还原（mksh 插桩）。\n"
    "   mksh 的保留字表是**运行期哈希表** keywords：单点 ktsearch，无宏展开、\n"
    "   无 bash 那种 find_reserved_word 死代码孪生，故插桩点更干净。\n"
    "   此处 ident 已由上方 memset 补零完毕、即将被 hash()/ktsearch 消费，\n"
    "   在此把别名换成真名，后续 ktsearch 即可命中原生 token 值。 */\n"
)

# L3 翻译实装（2026-09）：在 hash() 计算前把 ident 里的别名换成真名。
#   所有权契约：v7_isa_translate_kw 返回的是 isa_hook 内部视图（无命中返回
#   入参自身），必须立即 memcpy 拷回、不得持有指针——与 bash 侧 YT_NEW v3
#   "绝不夺取 token buffer 所有权"同一铁律。ident 是 char[IDENT+1]（sh.h:2362，
#   IDENT=64），ISA 别名 4-6 位、真名 ≤8 位，空间裕量充分；拷回后重新补零，
#   保持 mksh "ident 数组 NUL padded" 契约（lex.c 上方 memset 的注释要求）。
MKSH_L3_ANCHOR = MKSH_IDENT_LOOKUP + (
    "\t\tstruct tbl *p;\n"
    "\t\tuint32_t h = hash(ident);\n"
)
MKSH_L3_BODY = MKSH_KW_HEAD + (
    "\t{\n"
    "\t\textern const char *v7_isa_translate_kw(const char *);\n"
    "\t\tconst char *v7kw = v7_isa_translate_kw(ident);\n"
    "\n"
    "\t\tif (v7kw != NULL && v7kw != (const char *)ident) {\n"
    "\t\t\tsize_t v7l = strlen(v7kw);\n"
    "\n"
    "\t\t\tif (v7l <= IDENT) {\n"
    "\t\t\t\tmemcpy(ident, v7kw, v7l + 1);\n"
    "\t\t\t\tmemset(ident + v7l + 1, 0, (size_t)(IDENT - v7l));\n"
    "\t\t\t}\n"
    "\t\t}\n"
    "\t}\n"
) + MKSH_L3_ANCHOR

# ---- exec.c（L1 builtin + L2 外部命令 + L4 路径） ---------------------------
# 与 bash 的 execute_simple_command 单点对位：mksh 的命令解析全汇聚到
# findcom(name, flags) —— builtin 走 ktsearch(&builtins)、外部命令走
# search_path、别名走 ktsearch(&taliases)，三路都在这一个函数内。
#
# ⚠️ 硬约束（源码考古结论，改前必须重读）：
#   L1334 search_path() 内 `return (name);` —— **返回值可能与入参同指针**
#   （Linux 路径；OS/2 才走 real_exec_name）。findcom L1234 据此做
#   `if (npath.ro != name) afree(npath.rw, ATEMP);` 的判等释放。若在 findcom
#   入口【原地改写 name 指向的内容】，判等两边仍是同一指针 → 该释放判断失效 /
#   语义漂移。故本插桩【绝不触碰 name 指向的内存】，只把局部副本交给
#   findcom 的后续逻辑。
#
# 形态：findcom 入口处声明 `const char *v7nm = name;`，命中则换成
#   strdupx 的新串（ATEMP），并在函数退出前 afree。之后把函数体内全部
#   `name` 的**读取**改用 v7nm……成本高且易漏。改用更收敛的做法：
#   在入口把 name 重绑定为局部变量（C 允许 `name = v7nm;`？name 是
#   const char * 形参，可赋值 —— 赋值改的是**指针**不是内容，判等语义
#   `npath.ro != name` 仍成立：search_path 收到的是我们传进去的指针，
#   它 return(name) 时返回的正是同一个指针 ⇒ 判等两边一致，afree 逻辑不变）。
#
#   即：把形参指针重绑定为新串，入参内容一字不改（谁都没被写坏），
#   search_path 的返回值与【我们传入的那个指针】比较，语义自洽。
MKSH_FINDCOM_ANCHOR = (
    "\tstatic struct tbl temp;\n"
    "\tuint32_t h = hash(name);\n"
)
MKSH_FINDCOM_HEAD = (
    "/* V7 ISA L1/L2 还原（mksh 插桩，锚点 findcom 入口）。\n"
    "   命令名走 L1/L2（builtin + 外部命令）—— findcom 是 mksh 命令解析的\n"
    "   唯一汇聚点（builtins/functions/taliases/search_path 四路都在这）。\n"
    "\n"
    "   所有权设计（两条硬约束，改前必读）：\n"
    "     1) search_path L1334 `return (name)` 返回值可能与入参同指针，\n"
    "        findcom L1234 据此做 `npath.ro != name` 判等释放 ⇒ **绝不写\n"
    "        name 指向的内容**，只重绑定形参指针（判等两边仍同一指针，\n"
    "        search_path 收到并 return 的正是我们传入的那个 ⇒ 语义自洽）。\n"
    "     2) 调用方 ap[0] 之后还要拿去 execve ⇒ 更不能就地改内容。\n"
    "   栈缓冲 char[IDENT+1]：alias 14 字符 / 真名 ≤8 字符，容量绰绰有余；\n"
    "   **零堆分配** ⇒ 命中即拷贝到栈缓冲，函数任意出口都不需释放，\n"
    "   天然规避多出口（4 处 return）漏放。超长（理论不可能）则放弃翻译，\n"
    "   原名照跑 —— 与 bash 侧 v3「绝不夺取所有权」同一铁律。 */\n"
)
MKSH_FINDCOM_BODY = MKSH_FINDCOM_HEAD + (
    "\tchar v7_nmbuf[IDENT + 1];\n"
    "\tconst char *v7_nm = name;\n"
    "\n"
    "\t{\n"
    "\t\textern void v7_isa_translate_cmd(char **);\n"
    "\t\tchar *v7_tmp = (char *)v7_nm;\n"
    "\n"
    "\t\tv7_isa_translate_cmd(&v7_tmp);\n"
    "\t\tif (v7_tmp != (char *)v7_nm) {\n"
    "\t\t\tsize_t v7_l = strlen(v7_tmp);\n"
    "\n"
    "\t\t\tif (v7_l <= (size_t)IDENT) {\n"
    "\t\t\t\tmemcpy(v7_nmbuf, v7_tmp, v7_l + 1);\n"
    "\t\t\t\tv7_nm = v7_nmbuf;\n"
    "\t\t\t}\n"
    "\t\t}\n"
    "\t}\n"
    "\tname = v7_nm;\n"
) + MKSH_FINDCOM_ANCHOR

# ---- exec.c（L4 路径常量，com_ex 的 argv 数组） -----------------------------
# 挂点：`ap = (const char **)up;` 之后、`if (ap[0])` 之前 —— 必须在命令名被
#   findcom 消费【之前】完成，否则 ap[0] 里的路径（`./x/y` 形式）会漏翻。
#
# 为什么这里可以改 ap[] 元素：
#   up = eval(t->args, ...)，XPclose 用 **ATEMP 堆分配**数组本身，元素是
#   expand() 产出的堆串 —— 数组可写。ap 是 const char**，我们改的是
#   **指针槽**（`ap[i] = 新串`）而不是串内容 ⇒ 不写只读内存。
#   ⚠️ 早退路径（eval 里 `*ap == NULL` → 返回调用方数组）无参数词，天然无 L4。
#
# 生命周期：v7_isa_translate_paths 返回 strdup 堆串（新分配），此处的 up 数组
#   归本次命令的 ATEMP 块，命令结束整块回收 ⇒ 不 free 旧词（旧词归 ATEMP），
#   新串随命令结束后由 ATEMP 归还的**只有数组和 expand 的串**……新串是我们
#   strdup 的，严格说会泄漏。但 bash 侧同一位置的既有行为就是
#   `wl->word->word = np;`（旧串不 free，注释"归 unwind 栈管理"）——沿用它
#   的一致性：mksh 的 ATEMP 是**命令级 arena**，afree 只归还 arena 内指针，
#   我们的 strdup 串不在 arena 里，确属泄漏。
#   缓解：L4 路径在本轮只用于**冒烟验证**，且每个进程内命中次数=脚本中路径
#   常量个数（个位数），量级可忽略；正式接入时随 #28 批次执行器改成
#   arena 分配（alloc(len, ATEMP) + memcpy）即可零泄漏。此处先求"语义正确
#   可验证"，把泄漏面写进注释而不是假装没有。
MKSH_ARGV_ANCHOR = "\t\tap = (const char **)up;\n"
MKSH_ARGV_ANCHOR_NOINDENT = "ap = (const char **)up;\n"
MKSH_ARGV_HEAD = (
    "/* V7 ISA L4 路径常量还原（mksh 插桩，锚点 com_ex 的 argv 数组）。\n"
    "   遍历全部参数词做子串替换（含 ap[0]：`/x/y cmds` 形态的命令名里\n"
    "   也可能含路径）。只换指针槽不改串内容 —— 串可能来自只读字面量。\n"
    "   ⚠️ 已知泄漏：v7_isa_translate_paths 返回 strdup 堆串，本处未 free\n"
    "      （与 bash 侧同一位置行为一致）；冒烟阶段命中次数为个位数，可忽略，\n"
    "      正式接入时随 #28 改 arena 分配。 */\n"
)
MKSH_ARGV_BODY = MKSH_ARGV_HEAD + (
    "\t\tap = (const char **)up;\n"
    "\t\t{\n"
    "\t\t\textern char *v7_isa_translate_paths(const char *);\n"
    "\t\t\tint v7_i;\n"
    "\n"
    "\t\t\tfor (v7_i = 0; ap[v7_i] != NULL; v7_i++) {\n"
    "\t\t\t\tchar *v7_np = v7_isa_translate_paths(ap[v7_i]);\n"
    "\n"
    "\t\t\t\tif (v7_np != NULL)\n"
    "\t\t\t\t\tap[v7_i] = v7_np;\n"
    "\t\t\t}\n"
    "\t\t}\n"
)

# =============================================================================
# mksh R59c —— C1：builtin 接管 + 初始化挂载（路线 C）
# =============================================================================
#
# 目标：让 mksh 具备 bash 线三件套里的「builtin 接管」（L6 令牌化出口）
#      与「初始化挂载」两件能力。
#
# 为什么挂在 main.c 的 builtin 注册循环之后：
#   mksh 的 builtin 是**运行期哈希表** builtins（struct table），
#   由 main.c 的循环 `builtin(mkshbuiltins[i].name, mkshbuiltins[i].func)`
#   逐条 ktenter 进去。循环结束 = 表已建全 ⇒ 此时接管才找得到 "echo"。
#   早于循环会 get_builtin("echo") 返回 NULL（静默不接管）。
#
#   与 bash 的差异（挂点语义相同、实现不同）：
#     bash：shell_initialize() 之后，劫持静态数组 shell_builtins[].function
#     mksh：builtin 注册循环之后，改哈希表项 tp->val.f
#
# 初始化挂载（v7_isa_init 的显式触发）也放这里：
#   isa_hook.c 的两个翻译入口本来就**懒装载**（首次调用时 v7_isa_init），
#   所以这一步不是"必需"。但显式初始化有两个好处：
#     1) 把表解析开销从"首次命令执行"提前到"shell 启动"，行为更可预期；
#     2) v7_builtin_takeover_install 内部要查 L6 表（v7_isa_has_param_table），
#        若不先 init 则它自己会懒触发 —— 显式调用只是把顺序写明白。
#
# fail-closed（与 bash 线铁律一致）：
#   v7_builtin_takeover_install 内部先查 v7_isa_has_param_table()，
#   无 L6 表则**完全不接管** ⇒ 裸 mksh 跑普通脚本行为零变化。

# 声明区锚点：main.c 的 __RCSID 之后挂 extern 声明
MKSH_MAIN_RCSID = (
    '__RCSID("$MirOS: src/bin/mksh/main.c,v 1.374 2020/10/01 20:28:54 tg Exp $");\n'
)
MKSH_MAIN_DECLS = (
    "/* V7 C1：builtin 接管 + 初始化挂载（v7/mksh_poc/v7_builtin_takeover_mksh.c）。\n"
    "   extern 声明放这里而非 sh.h，是为了让插桩点集中在一个文件、便于审计。 */\n"
    "extern void v7_builtin_takeover_install(void);\n"
    "extern void v7_isa_init(void);\n"
)

# 挂载点锚点：builtin 注册循环结束、`if (!as_builtin) {` 之前。
# 取这么长的上下文是因为 `if (!as_builtin) {` 在 main.c 里出现两次（L323/L483），
# 只用它做锚点会命中错位置 —— 而错位置不会报错，只会静默少接管（极难查）。
# 前缀 `ccp = builtin_name; as_builtin = true; } }` 是循环体尾部，全文件唯一。
MKSH_MOUNT_ANCHOR = (
    "\t\t\tccp = builtin_name;\n"
    "\t\t\tas_builtin = true;\n"
    "\t\t}\n"
    "\t}\n"
    "\n"
    "\tif (!as_builtin) {\n"
)
MKSH_MOUNT_HEAD = (
    "/* V7 C1 挂载点（mksh 插桩）：builtin 注册循环之后。\n"
    "   此刻 builtins 哈希表已建全 ⇒ 接管 echo 才有目标。\n"
    "   v7_isa_init 先跑（查表开销提前到启动期），随后安装接管；\n"
    "   无 L6 表时 install 内部直接 return ⇒ 裸 mksh 行为不变。 */\n"
)
MKSH_MOUNT_BODY = MKSH_MOUNT_ANCHOR.replace(
    "\tif (!as_builtin) {\n",
    MKSH_MOUNT_HEAD +
    "\tv7_isa_init();\n"
    "\tv7_builtin_takeover_install();\n"
    "\n"
    "\tif (!as_builtin) {\n",
)

# =============================================================================
# mksh R59c —— C2：shf_open() 骨架注入层（路线 C）
# =============================================================================
#
# 目标：mksh 能直接跑"密文骨架"（自释放产物），形式对齐 bash 线的
#       zread.c.v7poc —— 但**劫持层不同**：bash 劫持读取层（zread），
#       mksh 劫持**打开层**（shf_open）。理由见 v7_shf_inject_mksh.c 文件头。
#
# 为什么选 shf_open：
#   · mksh 全树只有 5 个 shf_open 调用者，其中仅 2 个是脚本来源
#     （main.c:532 主脚本 / main.c:758 include）⇒ 一处覆盖全部脚本入口。
#   · 只改"打开"这一步，**读取语义零改动** ⇒ 顺带绕开 bash 线 elf 形态里
#     "mksh 把 8192 字节短读当 EOF"的阻塞项（memfd 可 seek、无短读问题）。
#
# 注入点：binopen3() 拿到 fd 之后、fd<0 错误分支之前。
#   取这里的理由：shf 结构体已分配好（shf/bsize/flags 都就位），
#   替换 fd 只需把 fd 换成注入 fd，后续 shf_reopen(fd, sflags, shf) 原样走 ——
#   改动面最小，且 shf 生命周期管理（afree/unwind）完全不受影响。
#
# fail-closed：v7_shf_inject 返回 -1 时**照常走 binopen3 的原结果**，
#   裸 mksh 跑普通脚本行为零变化。

MKSH_SHFOPEN_ANCHOR = (
    "\tfd = binopen3(name, oflags, mode);\n"
    "\tif (fd < 0) {\n"
    "\t\teno = errno;\n"
    "\t\tafree(shf, shf->areap);\n"
    "\t\terrno = eno;\n"
    "\t\treturn (NULL);\n"
    "\t}\n"
)
MKSH_SHFOPEN_BODY = (
    "\tfd = binopen3(name, oflags, mode);\n"
    "/* V7 C2 骨架注入（mksh 插桩，锚点 shf_open 的 binopen3 之后）。\n"
    "   受保护产物形态下，v7_shf_inject 返回一个指向【解密后明文】的\n"
    "   memfd；返回 -1 表示未激活或不是目标 ⇒ 沿用原生 fd，行为不变。\n"
    "   放在这里而不是替换 binopen3：shf 结构体已分配、错误清理路径\n"
    "   （afree + return NULL）保持不变，改动面最小。 */\n"
    "\t{\n"
    "\t\textern int v7_shf_inject(const char *);\n"
    "\t\tint v7_ifd = v7_shf_inject(name);\n"
    "\n"
    "\t\tif (v7_ifd >= 0) {\n"
    "\t\t\tif (fd >= 0)\n"
    "\t\t\t\tclose(fd);\n"
    "\t\t\tfd = v7_ifd;\n"
    "\t\t}\n"
    "\t}\n"
    "\tif (fd < 0) {\n"
    "\t\teno = errno;\n"
    "\t\tafree(shf, shf->areap);\n"
    "\t\terrno = eno;\n"
    "\t\treturn (NULL);\n"
    "\t}\n"
)


MKSH_R59C = {
    "name": "mksh-R59c",
    "files": {
        "kw": "lex.c",
        "com": "exec.c",
        "main": "main.c",
        "shf": "shf.c",
    },
    "ops": [
        {
            "file": "kw",
            "tag": "lex.c ktsearch(&keywords) L3 翻译实装",
            "kind": "replace",
            "site_old": MKSH_L3_ANCHOR,
            "site_new": MKSH_L3_BODY,
        },
        {
            "file": "com",
            "tag": "exec.c findcom 入口 L1/L2 翻译实装",
            "kind": "replace",
            "site_old": MKSH_FINDCOM_ANCHOR,
            "site_new": MKSH_FINDCOM_BODY,
        },
        {
            "file": "com",
            "tag": "exec.c com_ex argv 数组 L4 路径还原实装",
            "kind": "replace",
            "site_old": MKSH_ARGV_ANCHOR_NOINDENT,
            "site_new": MKSH_ARGV_BODY,
        },
        {
            "file": "main",
            "tag": "main.c 声明区 C1 extern 声明",
            "kind": "replace",
            "site_old": MKSH_MAIN_RCSID,
            "site_new": MKSH_MAIN_RCSID + MKSH_MAIN_DECLS,
        },
        {
            "file": "main",
            "tag": "main.c builtin 循环后 C1 初始化挂载 + builtin 接管",
            "kind": "replace",
            "site_old": MKSH_MOUNT_ANCHOR,
            "site_new": MKSH_MOUNT_BODY,
        },
        {
            "file": "shf",
            "tag": "shf.c shf_open 入口 C2 骨架注入层",
            "kind": "replace",
            "site_old": MKSH_SHFOPEN_ANCHOR,
            "site_new": MKSH_SHFOPEN_BODY,
        },
    ],
}


# 注册表：isa_hook.py --interp <name> 从这里取
ANCHOR_SETS = {
    "bash-5.2": BASH_52,
    "mksh-R59c": MKSH_R59C,
}

# 默认（向后兼容：不传 --interp 时用 bash-5.2，且沿用文件顺序参数）
DEFAULT_INTERP = "bash-5.2"
