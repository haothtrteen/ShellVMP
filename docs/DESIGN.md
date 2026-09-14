# sh-hook 通用设计 —— 自动发现 hook 点 + 表驱动插桩

> 本文档是浓缩版。完整论证（含 C 层移植路线对比、成本估算）见
> ShellVMP 仓库 `docs/GENERIC_HOOK_DESIGN.md` 与 `docs/C_LAYER_ROUTE_COMPARE.md`。

## 1. 问题

给 shell 解释器打 C 层插桩补丁（如 ShellVMP 的 `isa_hook.c` 四层令牌化），
每次换一个 shell 都要重新回答：

1. **往哪儿插**——hook 点在哪个文件哪个函数（以前靠逐行读源码）；
2. **怎么插**——插入、替换、回滚历史形态、保持幂等（以前散在一次性脚本里）。

本子项目把 1 自动化、把 2 表驱动化，使"移植到一个新 shell"的成本从
*通读源码* 降到 *跑一次扫描 + 写一张锚点表*。

## 2. 可行性：L3 保留字判定的同构

三个实测 shell 的保留字判定都是 `function(current_word) → 查表`：

| shell | 判定点 | 表 | 备注 |
|---|---|---|---|
| bash-5.2 | `CHECK_FOR_RESERVED_WORD` 宏（两处展开）+ 死代码孪生 `find_reserved_word` | `word_token_alist[]` | y.tab.c，yacc 生成 |
| mksh-R59c | `ktsearch(&keywords, ident, h)`（lex.c 单点） | `keywords` 运行时哈希 ← `tokentab[]` | syn.c 初始化表 |
| dash-0.5.12 | `findkwd(wordtext)` → `findstring(s, parsekwd)`（parser.c） | `parsekwd[]` | **构建时**由 mktokens 生成到 src/token_vars.h |

数据形态同构 ⇒ 发现器只需找一种形态：**数组，成员是保留字字符串**。

### 实测结果（Rule-1，三壳全中）

| shell | 发现 | 位置 | 命中 |
|---|---|---|---|
| bash-5.2 | `word_token_alist` | y.tab.c :4501 | 22 |
| mksh-R59c | `tokentab` | syn.c :789 | 15 |
| dash-0.5.12 | `parsekwd` | token_vars.h :69 | 16 |

## 3. 发现器（discover_tables.py）

算法：等长净化 → 找 `\w+\[\] = {` → 花括号配平 → 同偏移回原文提取字符串
→ 与保留字超集求交集 → 交集 ≥ `min_hit` 即候选。

三条坑（实现上真实踩过，测试 `tests/test_discover.sh` 已固化）：

1. **净化必须等长**——否则"净化文本定位、原文提取"的偏移全错；
2. **先剥字符串再配平花括号**——保留字表本身含 `"{"`/`"}"`；
3. **必须扫构建后的树**——dash 的表只在构建时生成。

## 4. 引擎（hook_engine.py）

锚点表（ANCHOR_SET）声明 `槽位 → 文件` 与 `ops`，三种 op：

| kind | 语义 | 幂等判据 |
|---|---|---|
| `append_after` | 在 anchor 后追加 new | `anchor+new` 在文中 |
| `prepend_before` | 在 anchor 前插入 new | `new+anchor` 在文中 |
| `replace` | site_old 整段替换为 site_new | site_new 在文中 |

每个 op 可带 `rollback: [(旧形态, 还原成), ...]`，用于源码树版本升级。

行为契约：幂等、响亮失败（exit 1 并指名 tag）、dry-run、回滚带
**"新形态不在文中"守卫**（防前缀包含导致的降级，真实事故：
`EC_DECL_EXTRA_V1` 是 `EC_DECL_EXTRA` 的前缀）。

### 三条铁律

1. **op 执行引擎只有一份**（`run_ops()`）——CLI 与库共用；两份循环必然漂移。
2. **回滚旧/新形态绝不互为子串**——设计时自检 `old in new`；引擎守卫是最后防线。
3. **插桩点必须在主执行路径**——bash 存在死代码孪生（`find_reserved_word`），
   打上去一切"成功"但什么也不发生；用探针验证命中后再上表。

## 5. 边界（自动化做不到的）

- **语义等价**：发现 ≠ 可插桩，主路径性必须人工/探针确认；
- **L1/L2 分发**：变量/参数展开层无同构表，仍需个案适配；
- **内存契约**：如 mksh `ident[IDENT]` 定长缓冲，插桩代码的缓冲假设需个案审查。

## 6. 状态与验证

- `tests/test_engine.sh`：11 断言全绿（自包含 fixture，覆盖铁律 1/2 的可执行证据）；
- `tests/test_discover.sh`：9 断言全绿（6 自包含 + 3 壳真实树，缺树 SKIP）；
- bash-5.2 生产锚点集：ShellVMP 仓库 `v7/bash_poc/anchors.py`（B0 重构后
  与旧脚本**字节级一致**，4/4 文件 md5 复现）；
- mksh-R59c L3：锚点表驱动插桩，`sh Build.sh -r` 编译通过，4 项构造等价检查通过。

## 7. 迁移记录

- 2026-09：`discover_tables.py` 自 ShellVMP `tools/hook_discover/` 迁入本仓库；
  `hook_engine.py` 自 ShellVMP `v7/bash_poc/isa_hook.py` 的 B0 表驱动重构抽出。
  ShellVMP 侧测试 `tests/test_hook_discover.sh` 改为指向兄弟仓库 `../sh-hook/`，
  缺仓库时 SKIP。
