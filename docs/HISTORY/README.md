# 历史归档（History Archive）

> 这里是 ShellVMP 的**发展史料**，不是可运行的产品。
>
> 归档目的有两个：**留下演进轨迹**（供复盘"当初为什么这么设计"），
> 以及**证明版权链条完整**（从最早原型到当前实现，作者与演化路径连续可查）。
>
> ⚠️ 这些文件**不参与构建、不参与测试、不保证能跑**。它们是时间切片。
> 当前实现请看 [`v6/`](../../v6)、[`v7/`](../../v7)、[`tools/`](../../tools)。

---

## 一、总览：四条演化线

| 目录 | 时期 | 内容 | 历史意义 |
|---|---|---|---|
| [`v0-prototypes/`](v0-prototypes/) | 2026-07 ~ 08 | 20 个早期脚本原型 | 从"调外部工具"到"自己写混淆器"的思路转变 |
| [`v5-v6-line/`](v5-v6-line/) | 2026-08 ~ 09 | TShell 系列 8 个主版本 | 从实验脚本到可用产品的迭代 |
| [`v7-loader-chain/`](v7-loader-chain/) | 2026-09 | V7 加固方案原始设计稿 | V7 加载器架构的**第一版思路** |
| [`t2-seccomp-experiments/`](t2-seccomp-experiments/) | 2026-09 | T2 反调试 A/B 实验 | "能不能防住 dump"的实证过程 |

**文件命名规则**：目录内文件带**数字前缀**（`00-`、`01-`…），
按时间/版本顺序排列。原始文件名（含中文名）已在下文对照表中保留。

---

## 二、`v0-prototypes/` —— 一切开始的地方

最早期的 20 个原型。这段的核心价值在于**展示了三次认知迭代**：

### 迭代 1：借轮子（v0.0）

| 文件 | 原始名 | 大小 | 说明 |
|---|---|---|---|
| `00-shc-openssl-wrapper.sh` | `shell加密混淆加固保护程序.sh` | 8.2 KB | 最早的一份。**直接包装 `shc` + `openssl` + `gpg`**，靠外部工具做加密 |
| `01-obfuscator-pure-bash.sh` | `shell_script_obfuscator.sh` | 9.2 KB | 同期的纯 bash 混淆器（SSOPT）。已开始自己写混淆逻辑。⚠️ **归档原文即不完整**——第 294 行引号未闭合（`bash -n` 报 unexpected EOF），是当时中途放弃的状态，原样保留 |
| `02-untitled.sh` | `untitled.sh` | 44 KB | 未命名系列起点，代码量骤增——开始做正经实现 |

### 迭代 2：功能堆叠（v0.1 ~ v0.3）

| 文件 | 原始名 | 说明 |
|---|---|---|
| `03-untitled_ds.sh` | `untitled_ds.sh` | 分支尝试 |
| `04-untitled_V3.sh` | `untitled_V3.sh` | 版本号出现，开始有意识迭代 |
| `05-main.sh` | `main.sh` | 主控脚本形态 |
| `06-` ~ `11-` | `untitled_V6/V7/V9/V10/V11/V12.sh` | 密集迭代期，20~30 KB 区间震荡 |

### 迭代 3：收敛与命名（v0.4）

| 文件 | 原始名 | 说明 |
|---|---|---|
| `12-untitled_V13.sh` | `untitled_V13.sh` | |
| `13-untitled_V13A.sh` | `untitled_V13A.sh` | 分支 A |
| `14-untitled_V13B.sh` | `untitled_V13B.sh` | 分支 B |
| `15-untitled_v13G.sh` | `untitled_v13G.sh` | 分支收敛（51 KB，体量最大） |
| `16-Thirteen_V4.sh` | `Thirteen_V4.sh` | **首次以作者名命名**——项目开始被当作"作品"而非"练习" |
| `17-ThirteenGP_Shell.sh` | `ThirteenGP_Shell.sh` | GP = 通用化尝试 |
| `18-GLM52_untitled.sh` | `GLM_5.2_untitled.sh` | 借助大模型辅助写的版本（命名留存了工具痕迹） |
| `19-GLM-V5_untitled.sh` | `GLM-V5_untitled.sh` | 同上 |

> **为什么这段值得留**：`00` 到 `17` 的对比，是一份完整的
> "从依赖现成工具 → 到自研保护机制"的化石记录。它同时回答了
> 一个常见问题——**为什么不直接用 shc**：因为 shc 只是编译成二进制，
> 内存里依然是明文，这段演进就是为了解决它。

---

## 三、`v5-v6-line/` —— TShell 产品化

`TShell` 是本项目正式的产品名（"Thirteen" + "Shell"）。这一线从
单文件脚本长到 120 KB，是 V6 混淆器的直接前身。

| 文件 | 原始名 | 大小 | 说明 |
|---|---|---|---|
| `20-TShell.sh` | `TShell.sh` | 64 KB | TShell 命名后的首个版本 |
| `21-TShell_V2.sh` | `TShell_V2.sh` | 71 KB | |
| `22-TShell_V3.sh` | `TShell_V3.sh` | 70 KB | |
| `23-TShell_V3.1.sh` | `TShell_V3.1.sh` | 71 KB | 小版本修补 |
| `24-TShell_V4L.sh` | `TShell_V4L.sh` | 78 KB | L = ?（原始注释未记，疑为 Lite/Long） |
| `25-TShell_V5.sh` | `TShell_V5.sh` | 97 KB | |
| `26-TShell_V6.sh` | `TShell_V6.sh` | 106 KB | **V6 混淆器的直接前身** |
| `27-TShell_V6.7F.sh` | `TShell_V6.7F.sh` | 120 KB | 该线终点（F = Final）。之后逻辑被抽进 [`v6/shell_script_obfuscator_v6.sh`](../../v6/shell_script_obfuscator_v6.sh) |

> **对照当前实现**：`27`（120 KB，单文件）→ `v6/shell_script_obfuscator_v6.sh`
> （3147 行）。**从"一个脚本什么都有"到"分层可维护"** 是这一步的关键跃迁。

---

## 四、`v7-loader-chain/` —— V7 设计原稿

| 文件 | 原始名 | 说明 |
|---|---|---|
| `00-V7-加固方案.md` | `6a7b5ae90a29a75ec3d921ee_V7_加固方案.md` | 文件名前缀是**云端文档 ID**，说明这份设计稿最初写在网上 |

这是 V7 加载器 + ISA 架构的**第一版思路稿**（2026-09-08）。
与最终实现的差异很有看头——哪些当初想对了、哪些被实测推翻。

> 与当前实现的对照见 [`../V7_DESIGN.md`](../V7_DESIGN.md) 与
> [`../ARCHITECTURE.md`](../ARCHITECTURE.md)。

---

## 五、`t2-seccomp-experiments/` —— T2 反调试的实证

**T2** 指威胁模型里的第 2 类攻击者：**能 dump 进程内存的本地攻击者**。
这一组实验用来回答一个问题：**加固后，攻击者还能不能读到明文？**

### 实验设计（A/B 对照）

| 文件 | 角色 |
|---|---|
| `victim.c` | **受害进程**：持有一段模拟业务明文（`S04 counter positive / SECRET_PAYLOAD_XYZ`），可切换"加固 / 未加固" |
| `probe.c` | **攻击者探针**：读 `/proc/<pid>/status` 的 `Dumpable`/`Seccomp` 字段，再尝试 `open("/proc/<pid>/mem")` 扫描明文 |
| `attacker.c` | **外部攻击者**（C 版）：只做 `open(/proc/pid/mem)` + 明文扫描 |
| `attacker.py` | 同上，Python 版 |
| `selftest.c` | **进程内自检**：在 bash 内部直接试 `ptrace(PTRACE_TRACEME)` 与 `process_vm_readv`（syscall 310） |
| `verify_sc.c` | 验证 seccomp 过滤规则是否生效 |

### 对照组脚本

| 脚本 | 场景 |
|---|---|
| `final_ab.sh` | **终验**：非 root 攻击者 dump「朴素 bash」vs「加固 bash」 |
| `root_ab.sh` | **最难场景**：root 攻击者视角——用来验证"防不住 root"这一判断 |
| `run_ab.sh` / `run_ab2.sh` | 早期两轮 A/B |
| `selfcheck.sh` | 在两个 bash 内部分别试 `ptrace` / `process_vm_readv` |

### 结论（已并入正式文档）

> **非 root 攻击者能被挡住**（`/proc/pid/mem` 打不开）；
> **root 攻击者挡不住**——这是实测得出的边界，不是猜测。

这一结论现在是 [`../THREAT_MODEL.md`](../THREAT_MODEL.md) 与
[`../PITFALLS.md`](../PITFALLS.md) 里"诚实边界"章节的实证来源。

| 相关文档 | 内容 |
|---|---|
| [`../THREAT_MODEL.md`](../THREAT_MODEL.md) | T1–T4 威胁分类与防线 |
| [`../PITFALLS.md`](../PITFALLS.md) | 实测打脸清单 |
| [`../../v7/bash_poc/v7_harden.c`](../../v7/bash_poc/v7_harden.c) | `v7_harden_memory2()` 的实现（`DONTDUMP` + `mlock`） |

---

## 六、为什么归档里没有二进制

- **体积**：原始 `TShell.zip` 解压 46 MB，其中约 40 MB 是编译产物
- **可复现**：有 `.c` + 构建脚本就够了，二进制可以重新编
- **安全**：不分发历史构建产物，符合 [`../OPEN_SOURCE_SCOPE.md`](../OPEN_SOURCE_SCOPE.md)
  "真机产物二进制不分发"的原则

被剔除的内容包括：`TShell_shellprotector_v6v7_r*.zip`（11 个版本包，含大量
重复构建产物）、`bash-vmp-aarch64-bionic-r33`（1 MB 二进制）、
`t2_seccomp` 下的 5 个已编译 ELF、以及 6 份内容重复的 `demo_app_wrapped.sh`。

---

## 七、许可

本目录全部内容沿用主仓库许可：**[AGPLv3](../../LICENSE) + [商业授权](../../LICENSE.COMMERCIAL)**。

历史脚本同样受版权保护——**归档不等于放弃权利**。

> Copyright (C) 2026 haothtrteen <2557976190@qq.com>
