#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
isa_hook.py —— r16 四层随机化表 C 端插桩器（对上游 bash 源，幂等）
================================================================================
用法： python3 isa_hook.py <execute_cmd.c> <y.tab.c> <variables.c> <shell.c>
  任一锚点不匹配 → exit 1（防静默错位，与 xtrace_kill.py 同哲学）
  已 patch → 原样跳过（幂等，重构建安全）

插桩点（对应 v7/bash_poc/isa_hook.c）：
  execute_cmd.c
    1) 声明区：execute_simple_command PARAMS 行后挂 extern
    2) 插桩：execute_simple_command 内 `lastarg = (char *)NULL;` 之后、
       首个分派读取（find_special_builtin）之前 → 命令词翻译
       （单点覆盖 builtin/external/function/execve 全部分派路径）
  y.tab.c
    1) 声明：find_reserved_word 定义前挂 extern
    2) 插桩：find_reserved_word 查表前翻译 tokstr（L3 保留字还原）
  variables.c
    插桩：find_variable 查表前翻译位置参数别名（L4 参数还原）
  shell.c（r27 / T1）
    插桩：shell_initialize() 之后挂自定义 builtin 接管安装点
       （v7_builtin_takeover_install，劫持 shell_builtins[].function）

注意：只动词翻译，不动任何检测/控制流；无表时翻译函数空转，行为与
未魔改 bash 完全一致（v7_isa_init 失败静默是设计约束）。
"""
import sys

# ---- execute_cmd.c ----
EC_DECL_ANCHOR = (
    "static int execute_simple_command "
    "PARAMS((SIMPLE_COM *, int, int, int, struct fd_bitmap *));\n"
)
EC_DECL_EXTRA = (
    "/* r16：V7 ISA 表翻译（v7/bash_poc/isa_hook.c；alias→orig 单点还原） */\n"
    "extern void v7_isa_translate_cmd PARAMS((char **));\n"
    "extern char *v7_isa_translate_paths PARAMS((const char *));\n"
)
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

# ---- y.tab.c ----
# r16 教训：find_reserved_word 是【旁路死代码】（无调用者），词法主路径是
# CHECK_FOR_RESERVED_WORD 宏（read_token 内两处展开，直接遍历 word_token_alist）。
# 初版 patch 到死代码上，L3 看似构建成功实则全程未还原。
# 宏体首行插翻译：tok 是宏参数，展开后即对调用方 token 变量赋值还原。
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


# r16-5 形态（命令词 + 全部参数词的路径还原），见上
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
# r16-3 旧形态的声明块（只有 translate_cmd），就地升级用
EC_DECL_EXTRA_V1 = (
    "/* r16：V7 ISA 表翻译（v7/bash_poc/isa_hook.c；alias→orig 单点还原） */\n"
    "extern void v7_isa_translate_cmd PARAMS((char **));\n"
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


def _patch(text, old, new, tag, site_old=None, site_new=None):
    # 幂等：任一"已应用"形态在文中出现即跳过（new 为 None 时只看 site_new）
    already = (site_new is not None and site_new in text) or \
              (new is not None and new in text)
    if already:
        print("  %s：已 patch，跳过（幂等）" % tag)
        return text
    if old not in text:
        sys.stderr.write("错误：%s 锚点不匹配（bash 源码结构已变？）\n" % tag)
        sys.exit(1)
    if site_old is not None:
        if site_old not in text:
            sys.stderr.write("错误：%s 插桩点不匹配\n" % tag)
            sys.exit(1)
        return text.replace(site_old, site_new, 1)
    return text.replace(old, new, 1)


def main():
    if len(sys.argv) != 5:
        sys.stderr.write("用法: python3 isa_hook.py <execute_cmd.c> "
                         "<y.tab.c> <variables.c> <shell.c>\n")
        sys.exit(2)
    ec_path, yt_path, var_path, sh_path = (sys.argv[1], sys.argv[2],
                                           sys.argv[3], sys.argv[4])

    with open(ec_path, "r", encoding="utf-8") as f:
        ec = f.read()
    # r16-5 升级：旧树里已是 r16-3 形态（只做命令词翻译 / 声明块缺
    # translate_paths），先把旧形态回滚再重新应用——否则幂等检查
    # （新形态缺席 + 旧锚点缺席）会误判"源码结构已变"。
    if EC_DECL_EXTRA_V1 in ec and EC_DECL_EXTRA not in ec:
        ec = ec.replace(EC_DECL_EXTRA_V1, EC_DECL_EXTRA, 1)
        print("  execute_cmd.c：声明块补齐 v7_isa_translate_paths")
    if EC_SITE_NEW_V1 in ec and EC_SITE_NEW not in ec:
        ec = ec.replace(EC_SITE_NEW_V1, EC_SITE_OLD, 1)
        print("  execute_cmd.c：检测到 r16-3 旧形态，已回滚待升级")
    ec = _patch(ec, EC_DECL_ANCHOR, EC_DECL_ANCHOR + EC_DECL_EXTRA,
                "execute_cmd.c 声明")
    ec = _patch(ec, EC_SITE_OLD, None, "execute_cmd.c 插桩",
                site_old=EC_SITE_OLD, site_new=EC_SITE_NEW)
    with open(ec_path, "w", encoding="utf-8") as f:
        f.write(ec)
    print("  execute_cmd.c：命令词翻译插桩完成")

    with open(yt_path, "r", encoding="utf-8") as f:
        yt = f.read()
    for old_form in (YT_NEW_V1, YT_NEW_V2):
        if old_form in yt and YT_NEW not in yt:
            yt = yt.replace(old_form, YT_OLD, 1)
            print("  y.tab.c：检测到上一版 hook 形态，已回滚待升级")
            break
    yt = _patch(yt, YT_OLD, YT_NEW, "y.tab.c CHECK_FOR_RESERVED_WORD")
    with open(yt_path, "w", encoding="utf-8") as f:
        f.write(yt)
    print("  y.tab.c：保留字翻译插桩完成")

    with open(var_path, "r", encoding="utf-8") as f:
        var = f.read()
    var = _patch(var, VAR_OLD, VAR_NEW, "variables.c find_variable")
    with open(var_path, "w", encoding="utf-8") as f:
        f.write(var)
    print("  variables.c：位置参数翻译插桩完成")

    with open(sh_path, "r", encoding="utf-8") as f:
        sh = f.read()
    sh = _patch(sh, SC_OLD, SC_NEW, "shell.c builtin 接管安装点")
    with open(sh_path, "w", encoding="utf-8") as f:
        f.write(sh)
    print("  shell.c：自定义 builtin 接管安装点插桩完成")

    print("ISA hook patch 全部应用")


if __name__ == "__main__":
    main()
