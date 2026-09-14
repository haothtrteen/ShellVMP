# sh 通用 hook 点 —— 便捷快速移植不同 sh 解释器的特性

给 POSIX shell 解释器打 C 层插桩补丁时，最难的一步是「往哪儿插」：每个 shell
的保留字表叫什么名字、在哪个文件、以什么形态存在，事先不知道，传统做法只能
逐个读源码。本子项目把这一步**自动化**了，并把插桩本身做成**表驱动**。

一句话：**发现器告诉你往哪儿插，引擎负责怎么插。**

```text
┌──────────────────────┐      候选位置        ┌──────────────────────┐
│ discover_tables.py   │ ───────────────────▶ │ 人工确认语义等价       │
│ 自动扫"保留字表"形态   │                      │ （是否在主执行路径？）  │
└──────────────────────┘                      └──────────┬───────────┘
                                                         ▼ 写成锚点表
                                              ┌──────────────────────┐
                                              │ hook_engine.py       │
                                              │ 定位→回滚→幂等→插入    │
                                              └──────────────────────┘
```

## 快速开始

```bash
# 0. 跑自带回归（引擎部分自包含，无需真实 shell 源码）
bash tests/test_engine.sh

# 1. 构建（必须！见"三条坑"第 3 条）目标 shell 后，扫它的源码树
make -C /path/to/dash-0.5.12          # 先 ./configure && make
python3 discover_tables.py /path/to/dash-0.5.12/src

# 2. 拿到候选位置后，写锚点表（格式见 examples/anchors_example.py）
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
   展开并存），打到死代码上一切都"成功"且什么也不发生——用探针验证命中
   后再上表。

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

## License

MIT，见 [LICENSE](LICENSE)。
