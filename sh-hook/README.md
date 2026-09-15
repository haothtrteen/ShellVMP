# sh 通用 hook 点 —— 便捷快速移植不同 sh 解释器的特性

给 POSIX shell 解释器打 C 层插桩补丁时，最难的一步是「往哪儿插」：每个 shell
的保留字表叫什么名字、在哪个文件、以什么形态存在，事先不知道，传统做法只能
逐个读源码。本子项目把这一步**自动化**了，并把插桩本身做成**表驱动**。

一句话：**发现器告诉你往哪儿插，引擎负责怎么插。**

```text
┌──────────────────────┐   保留字表（G1）     ┌──────────────────────┐
│ discover_tables.py   │ ───────────────────▶ │ discover_callers.py  │
│ 自动扫"保留字表"形态   │   表名                │ 查表函数/宏/容器链/    │
└──────────────────────┘                      │ 调用点引用图谱（G2）   │
                                              └──────────┬───────────┘
                                                         ▼ 候选
                                              ┌──────────────────────┐
                                              │ probe_path.py（G3）  │
                                              │ 自动探针裁决主路径     │
                                              └──────────┬───────────┘
                                                         ▼ 确认主路径
                                              ┌──────────────────────┐
                                              │ 写成锚点表            │
                                              └──────────┬───────────┘
                                                         ▼
                                              ┌──────────────────────┐
                                              │ hook_engine.py       │
                                              │ 定位→回滚→幂等→插入    │
                                              └──────────────────────┘
```

## 快速开始

```bash
# 0. 跑自带回归（自包含，无需真实 shell 源码）
bash tests/test_engine.sh
bash tests/test_callers.sh

# 1. 构建（必须！见"三条坑"第 3 条）目标 shell 后，扫它的源码树
make -C /path/to/dash-0.5.12          # 先 ./configure && make
python3 discover_tables.py /path/to/dash-0.5.12/src

# 2. 从 G1 发现的表出发，画出引用图谱（查表函数/宏/调用点）
python3 discover_callers.py /path/to/dash-0.5.12/src --from-g1
#   或手动指定表：python3 discover_callers.py <目录> --table parsekwd

# 3. 拿不准哪个候选在主执行路径？让探针替你裁决：
#    自动插桩 → 增量构建 → 跑探针脚本 → 报告命中/未命中
python3 probe_path.py --srcdir /path/to/dash-0.5.12/src \
    --build-cmd "make" --shell /path/to/dash-0.5.12/src/dash
#   表名省略 --table 时自动跑 G1；--json 输出机器可解析结果

# 4. 确认主路径后，写锚点表（格式见 examples/anchors_example.py）
python3 hook_engine.py examples/anchors_example.py --list
python3 hook_engine.py examples/anchors_example.py --srcdir <源码树> --dry-run
python3 hook_engine.py examples/anchors_example.py --srcdir <源码树>
```

## 为什么可行：L3 保留字判定的三壳同构

三个 shell 的"这个词是不是保留字"判定，在数据形态上是同一件事——
`function(current_word) → 查某张表`：

| shell | 判定点 | 表 | 表的位置 |
|---|---|---|---|
| bash-5.2 | `CHECK_FOR_RESERVED_WORD` 宏 | `word_token_alist[]` | y.tab.c（yacc 生成） |
| mksh-R59c | `ktsearch(&keywords, ident, h)` | `tokentab[]` 喂进运行时哈希 | syn.c |
| dash-0.5.12 | `findkwd(wordtext)` → `findstring` | `parsekwd[]` | token_vars.h（**构建时**由 mktokens 生成） |

所以发现器只需要找一种形态：**一个数组，成员是保留字字符串**。

### G2 引用图谱（discover_callers.py）实测

从 G1 的表出发自动画出"表 → 查表函数 → 调用点"：

| shell | 自动发现的主路径候选 |
|---|---|
| bash | 宏 `CHECK_FOR_RESERVED_WORD` 展开点 `read_token_word` y.tab.c:7556/7573（与 ShellVMP 手工插桩选择一致）；旁路 `find_reserved_word` 仅 print_cmd.c:1398 一处 |
| mksh | 容器链 `tokentab → keywords` → `ktsearch(&keywords,...)` 调用点 **lex.c:1046（yylex）**/ tree.c:776 / funcs.c:653 |
| dash | `findkwd`（parser.c:1632）→ 调用点 parser.c:725 + exec.c:788 |

运行时哈希型 shell（mksh）的表只被"喂表"函数引用，真实查询在容器上——
发现器按"枚举表 + `&容器` 实参"特征自动展开容器链，并凭"表被整体当实参
消费"（查询形态）及时停住。

### G3 主路径探针（probe_path.py）实测

候选混着主路径、旁路、死代码——打到旁路上一切"成功"且什么也不发生。
G3 自动完成裁决：给候选插 `write(2, "[PROBE] ...")` 探针（零头文件依赖）
→ 增量构建 → 跑探针脚本 → 收集 stderr 命中：

| shell | 命中（主执行路径） | 自动拒绝（未命中） |
|---|---|---|
| bash | `CHECK_FOR_RESERVED_WORD()@read_token_word` y.tab.c | `find_reserved_word`（y.tab.c func-ref + print_cmd.c:1398 旁路调用） |
| mksh | `yylex` lex.c:1046 | tree.c / funcs.c（编辑器补全路径） |
| dash | `findkwd()@readtoken` parser.c:725 | exec.c:788（describe_command）——**脚本覆盖不足**而非死代码，默认探针脚本没构造 `command -V` |

最后一条是 G3 的边界：**裁决依赖探针脚本的覆盖面**。未命中只说明
"这次没跑到"，不等于死代码——人工裁决旁路前先检查脚本是否触达了
相关构造。

## 三条坑（发现器，改代码前先读）

1. **净化必须等长**：剥注释/字符串要用等长空白替换。否则"用净化文本定位、
   回原文取内容"的偏移全乱——第一版原型的症状就是"匹配上了却什么也取不到"
   （26538 字符被剥成 21445）。
2. **先剥字符串，再配平花括号**：保留字表里就含 `"{"`/`"}"` 字面量，朴素
   花括号计数永远不会配平（实测吃穿 8580 字符）。
3. **必须扫构建过的树**：dash 的 `parsekwd[]` 在构建时才生成到
   `src/token_vars.h`，只扫 pristine tarball 会漏掉。

## 三条铁律（引擎，全部来自真实事故）

1. **op 执行引擎只能有一份**。CLI 与 library 入口只做参数解析和文件读写，
   op 的执行必须全部走 `run_ops()`。两份循环必然漂移——第一个症状是部分
   op 的成功日志丢失。
2. **回滚的旧形态与新形态绝不能互为子串**。设计锚点表时先自检
   `old in new`：若旧形态是新形态的前缀，无守卫的回滚会把已升级的树**降级**
   回去（真实事故：`EC_DECL_EXTRA_V1` 是 `EC_DECL_EXTRA` 的前缀）。引擎的
   "新形态不在文中"守卫是最后防线，不是设计借口的替代品。
3. **插桩点必须在主执行路径**。发现器产出的是候选不是结论。bash 里存在
   死代码孪生函数（`find_reserved_word` 与活的 `CHECK_FOR_RESERVED_WORD`
   展开并存），打到死代码上一切都"成功"且什么也不发生——用
   `probe_path.py` 探针验证命中后再上表。

## 边界：自动化不了的

- **语义等价**：发现器只认数据形态，"这个点是否在主执行路径"必须人工/探针确认。
- **L1/L2 词法分发**：保留字表只覆盖 L3；变量/参数展开层的插桩点形态各异。
- **内存契约**：插桩代码对缓冲区寿命、拷贝边界的假设（如 mksh `ident[IDENT]`
  定长缓冲）因 shell 而异，需个案审查。

## 出身与血统

从 [ShellVMP](https://example.invalid/shellvmp)（v7/bash_poc）的插桩工作中
抽出：

- `hook_engine.py` ← `v7/bash_poc/isa_hook.py` 的 B0 表驱动重构（引擎部分）；
- `discover_tables.py` ← ShellVMP `tools/hook_discover/`（已迁移至此）；
- bash-5.2 全套生产锚点集与 mksh-R59c 试验性 L3 锚点集**留存于 ShellVMP 仓库**
  （`v7/bash_poc/anchors.py`），此处只含引擎与示例锚点集。

## 测试

| 测试 | 覆盖 | 依赖 |
|---|---|---|
| `tests/test_engine.sh`（11 断言） | 插桩/编译运行/幂等/dry-run/响亮失败/历史回滚/前缀陷阱/--list/库路径同引擎 | 无（自包含 fixture） |
| `tests/test_discover.sh`（9 断言） | 语法/合成表发现/低命中拒绝/可复现/净化等长/花括号抗干扰 + 三壳真实树 | 可选：BASH_SRC_DIR / MKSH_SRC_DIR / DASH_SRC_DIR（缺则 SKIP） |
| `tests/test_callers.sh`（9 断言） | direct 调用链/死代码无调用者/宏展开点/容器链/可复现 + 三壳真实树 | 同上 |
| `tests/test_probe.sh`（6 断言） | 活路径命中/死代码不命中/探针幂等（重跑语义一致且不重复插针）+ 三壳真实树裁决 | 同上 |

## License

MIT，见 [LICENSE](LICENSE)。
