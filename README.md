# ShellVMP

**把 shell 脚本变成自保护产物。** 两层独立可用的保护：

- **V6** — 纯 shell 实现的脚本混淆器：分块加密 + 执行状态绑链 + 跳跃密钥链 + 批级自修改。零外部依赖（`aes` 模式需 openssl，`builtin` 模式纯 shell/awk）。
- **V7** — ELF 封装层：反调试 + 反内存读取 + 流式解密直喂解释器，磁盘上永不存在完整明文。
- **V7-ISA** — 解释器魔改层（PoC）：把命令名/关键字/变量名令牌化，让产物在磁盘上只是一串随机令牌。

> 目标不是"藏得更深"，而是**改变攻击面**：让磁盘上不存在明文，让运行期的明文窗口尽可能短且有界，让关键逻辑变成攻击者无法静态分析的虚拟指令。

---

## 目录

- [它是怎么工作的](#它是怎么工作的)
- [三分钟上手](#三分钟上手)
- [为什么 shell 是最难保护的语言](#为什么-shell-是最难保护的语言)
- [诚实的安全边界](#诚实的安全边界)
- [项目结构](#项目结构)
- [版本演进与心路历程](docs/JOURNEY.md)
- [文档索引](#文档索引)
- [状态与路线图](#状态与路线图)

---

## 它是怎么工作的

```
┌─────────────────────────────────────────────────────────────┐
│  你的脚本 (app.sh)  ── 明文，谁都看得懂                      │
└────────────────────────┬────────────────────────────────────┘
                         │
              ┌──────────▼──────────┐
              │   V6  混淆器         │  纯 shell 实现
              │  ─────────────────   │
              │  分块 → 加密 → 绑链   │  · 每块密文独立
              │  + 诱饵 + 垃圾块     │  · 执行状态($?/$_/路径)掺入密钥链
              └──────────┬──────────┘  · 跳跃引用第 N-7 块 → 必须从头跑
                         │                · 批级自修改（解密后重加密）
                         ▼
                  骨架 (加密的 shell 脚本)
                         │
              ┌──────────▼──────────┐
              │   V7  ELF 封装       │  C 实现
              │  ─────────────────   │
              │  scrypt-like KDF     │  · 载荷追加在 ELF 尾部
              │  Encrypt-then-MAC    │  · 父进程分块解密 → pipe → 子进程
              │  pipe 流式执行        │  · 明文即写即抹，不进磁盘
              └──────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │   V7-ISA 令牌化      │  魔改解释器
              │  ─────────────────   │
              │  命令名/关键字/变量   │  · L1 builtin / L2 external
              │  → 随机别名          │  · L3 关键字 / L4 变量+路径
              └──────────┬──────────┘  · L6 字符串字面量（密文驻留）
                         ▼
                    最终产物 (ELF)
              strings 出来的只有随机令牌
```

## 三分钟上手

### 最小用法：V6 混淆

```bash
git clone https://github.com/<you>/ShellVMP.git
cd ShellVMP

# 混淆一个脚本
ANDROID_GATE=0 bash v6/shell_script_obfuscator_v6.sh examples/demo_app.sh demo.protected.sh

# 跑它
bash demo.protected.sh
```

`ANDROID_GATE=0` 用于在非安卓环境测试；默认开启安卓环境门控（非安卓直接静默拒绝）。

### 常用开关

```bash
# 强混淆：加垃圾块 + 诱饵
JUNK_LEVEL=3 DECOY_LEVEL=2 \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh

# 密钥分离：产物需要口令才能跑，主密钥不写入产物
PASSKEY_MODE=1 PASSKEY_COUNT=3 \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh

# 零 openssl 依赖（极简环境）
CRYPTO_MODE=builtin \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh
```

### 混淆前体检（推荐）

```bash
python3 tools/v6_lint.py your_script.sh          # 静态检查兼容性
python3 tools/v6_lint.py your_script.sh --strict # 有问题即 exit 1（可挂 CI）
```

> **为什么必须先体检**：宿主的 `errexit`、`set -x`、改 `PS4`、重定义 builtin 都会**命中产物的反调试指纹** → 主密钥污染 → **静默 exit、零提示**。`v6_lint.py` 会在混淆前把这些揪出来。

### 署名 / 个人化

三种方式，**安全性递增**：

```bash
# ① 命名空间前缀（推荐）：产物里是 yourname_k9x2
#    每次构建后缀都不同 → 攻击者无法写固定规则
V6_NS=yourname ANDROID_GATE=0 \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh

# ② 抗 AI 声明（嵌入明文头部，正常用户不可见）
AI_GUARD=1 AI_GUARD_OWNER="Your Name" ANDROID_GATE=0 \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh
```

> **为什么不建议把标识做成完全固定的变量名**：随机变量名存在的**唯一理由**就是"不固定"。
> 固定 = 给攻击者一个**永久锚点**——一条 `grep` 就能定位密钥链的每一环，并可用**跨样本比对**反推结构。
> `V6_NS` 的"前缀 + per-build 随机后缀"是**署名感与安全性的两全方案**。

### 运行期排障

```bash
bash tools/v6_pm_diag.sh    # 逐条列出 6 项会触发密钥污染的条件
```

---

## 为什么 shell 是最难保护的语言

| 难点 | 说明 |
|---|---|
| **输入即源码** | 解释器必须能读懂代码 → 攻击者也能。没有 AOT 这道天然屏障 |
| **无编译期** | 不能像 C 那样"编译时算好"，所有密钥派生都发生在运行期 |
| **进程即边界** | 每一次 `$( )` / `\|` 都可能是密钥或明文泄漏点（`/proc/pid/cmdline`） |
| **字符串即一切** | 变量、函数、命令都是字符串，没有类型系统帮你"固化"语义 |
| **内建被特权** | 攻击者重定义 `eval` / `type` 就能劫持你的整个执行链 |

**反过来看，这也带来了独特优势**：shell 没有二进制，所以**每一行都可以是密文**——粒度优势是编译型语言不具备的。

## 诚实的安全边界

> **这一节是本项目最重要的部分。任何声称"无法破解"的脚本保护都是骗局。**

### 挡得住什么

- ✅ **随手看源码**、`cat` 一下就知道逻辑
- ✅ **静态批量扒取**（爬虫/批量去混淆）
- ✅ **明文落盘分析**（磁盘上不存在完整明文）
- ✅ **非 root 的内存读取**（`PR_SET_DUMPABLE=0` + seccomp-BPF，唯一确定性手段）
- ✅ **调试器/注入**（TracerPid / frida 痕迹扫描 / `LD_PRELOAD`）

### 挡不住什么

| 攻击者能力 | 现实 |
|---|---|
| **root 权限** | 能读 `/proc/pid/mem`（`PROT_NONE` 拦不住它——走 `get_user_pages`，不检查页表权限）。**实测打脸过** |
| **足够长的运行期观察** | 解释器最终要吃明文。唯一能做的是**缩短窗口 + 稀释信噪比** |
| **耐心的人工逆向** | 任何混淆都是"提高成本"，不是"消除可能"。目标是"让逆向成本高于收益" |
| **有 AI 辅助** | 抗 AI 声明（`AI_GUARD=1`）能挡住一部分，但**不构成技术防线** |

### 一句话

> **整体强度 ≈ 最弱组件，且所有组件共享信任根（dump 一次全暴露）。**
> 我们不承诺"无法破解"，只承诺"**逆向成本 > 你的脚本价值**"。

详见 [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)。

---

## 项目结构

```
ShellVMP/
├── v6/
│   └── shell_script_obfuscator_v6.sh   # V6 混淆器（纯 shell，~2900 行）
├── v7/
│   ├── elfrun.c                        # ELF 封装加载器
│   ├── crypto_core.h                   # 密码学核心（SHA-256/HMAC/流密码/scrypt-like）
│   ├── v7_wipe.h                       # 内存擦除
│   ├── v7_build.sh                     # V7 构建入口
│   ├── v7_wrap.sh                      # V7 一键封装
│   ├── blobgen.c                       # 载荷生成
│   └── bash_poc/                       # V7-ISA 解释器魔改 PoC
│       ├── isa_hook.c / .py            # 四层令牌化表：C 端翻译 + Python 端插桩
│       ├── crypto_isa.h                # ISA 层密码学
│       ├── xtrace_kill.py              # 调试通道剥离
│       ├── elf_anti_disasm.py          # 抗反汇编后处理
│       └── ...
├── tools/
│   ├── v6_lint.py                      # V6 混淆前兼容性检查（含 41 项自测）
│   ├── v6_pm_diag.sh                   # 运行期指纹诊断
│   ├── v7_isa.py                       # 四层表生成器 + 校验器
│   ├── isa_itest.py                    # ISA 端到端集成测试
│   ├── vmp_apply.py                    # VMPacker 自动化对接（逐函数验证闭环）
│   ├── vmp_targets.py                  # 无符号表产物里定位保护函数
│   └── argv_leak_scan.py               # 参数泄漏扫描
├── examples/                           # 示例脚本
├── tests/                              # 回归测试
└── docs/                               # 文档
    ├── JOURNEY.md                      # ★ v1→v6 心路历程
    ├── ARCHITECTURE.md                 # 架构与设计原理
    ├── THREAT_MODEL.md                 # 威胁模型与能力承诺
    └── ...
```

## 文档索引

| 想了解 | 读 |
|---|---|
| **这套东西是怎么一路试错做出来的** | **[`docs/JOURNEY.md`](docs/JOURNEY.md)** |
| 两层架构怎么协作、密码学怎么设计 | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| 到底防得住谁、防不住谁 | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) |
| V6 的分块/绑链/跳跃密钥链算法 | [`docs/V6_DESIGN.md`](docs/V6_DESIGN.md) |
| V7 的流式解密与反调试 | [`docs/V7_DESIGN.md`](docs/V7_DESIGN.md) |
| 令牌化（V7-ISA）四层表 | [`docs/TOKENIZATION.md`](docs/TOKENIZATION.md) |
| 构建、测试、排障 | [`docs/BUILD.md`](docs/BUILD.md) |
| **踩过的坑（按症状索引）** | **[`docs/PITFALLS.md`](docs/PITFALLS.md)** |
| VMP 对接与收益边界 | [`docs/VMP_NOTES.md`](docs/VMP_NOTES.md) |
| 哪些开源、哪些保留、为什么 | [`docs/OPEN_SOURCE_SCOPE.md`](docs/OPEN_SOURCE_SCOPE.md) |
| 路线图与已知限制 | [`docs/ROADMAP.md`](docs/ROADMAP.md) |

### 最值得读的三篇

如果你只有十分钟，按这个顺序：

1. **[`docs/JOURNEY.md`](docs/JOURNEY.md)** —— v0 到 v6 的完整试错过程。每一节都是"我以为这样就行了 → 实测被打脸 → 改成这样"。**失败的方式比成功的方式更有信息量。**
2. **[`docs/PITFALLS.md`](docs/PITFALLS.md)** —— 按症状索引的踩坑清单，含"我以为但实测打脸"的六条。
3. **[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)** —— 诚实的能力边界。**任何声称"无法破解"的脚本保护都是骗局。**

## 状态与路线图

| 层 | 状态 | 说明 |
|---|---|---|
| **V6 混淆器** | ✅ 稳定 | 双架构（x86_64 / aarch64）验证；32 项集成测试 |
| **V7 ELF 封装** | ✅ 稳定 | 反调试 / 流式解密 / 内存擦除；退出码分类 |
| **V7-ISA 令牌化** | 🧪 PoC | L1-L4 已通，L6 字符串字面量部分完成；A 线/B 线双路线 |
| **VMP 对接** | 🧪 工具就绪 | `vmp_apply.py` 逐函数验证闭环；受限于 NEON 约束，**收益有限**（见文档） |
| **Python / Lua 移植** | 📋 方法论已备 | 机制可移植性分析完成，待实现 |

### 已知限制

- **V7-ISA 绑定 bash 5.2**（解释器魔改层的插桩点依赖具体源码结构）。bash 主版本升级时需要重新校准插桩点——这层是"可移植性最弱、但价值最高"的部分。
- **VMP 保护收益有限**：本架构最终把脚本交给 `eval`，VMP 只能保护"壳"。详见 [`docs/VMP_NOTES.md`](docs/VMP_NOTES.md)。
- **真机产物**未随仓库分发（体积 + 隐私）。
- **产物运行期锁定 bash**（非语法限制，是密钥链把解释器语义烧进了密文）。跨 shell 的完整分析、功能剥离表与三档路线见 [`docs/GENERALIZATION_FEASIBILITY.md`](docs/GENERALIZATION_FEASIBILITY.md)。**注**：目标机无需装 bash —— `V7_SELF=1` 内嵌静态解释器即可跨平台运行。

---

## License

[MIT](LICENSE) — 见 [`LICENSE`](LICENSE)。

**免责声明**：本项目是**防御性安全研究**。使用者应只在**自己拥有或被授权**的代码上使用。作者不对任何滥用行为负责。
