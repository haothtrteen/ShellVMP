# 构建、测试与排障

---

## 一、环境要求

| 组件 | 要求 |
|---|---|
| **bash** | 5.1+（V6 需要 `$RANDOM` 的 Park-Miller 行为） |
| **openssl** | 任意近期版本（`aes` 模式需要；`builtin` 模式不需要） |
| **gzip / sha512sum / sha256sum** | 标准工具 |
| **python3** | 3.8+（工具脚本） |
| **gcc/clang** | 构建 V7 需要（交叉编译需对应工具链） |
| **capstone**（可选） | VMP 工具的函数边界精修与 NEON 体检 |

```bash
# 可选依赖
pip install capstone
```

---

## 二、V6：最快的开始

```bash
# 混淆
ANDROID_GATE=0 bash v6/shell_script_obfuscator_v6.sh input.sh output.sh

# 运行
bash output.sh
```

### 常用开关

```bash
# 强混淆
JUNK_LEVEL=3 DECOY_LEVEL=2 ANDROID_GATE=0 \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh

# 密钥分离（产物需要口令）
PASSKEY_MODE=1 PASSKEY_COUNT=3 ANDROID_GATE=0 \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh

# 零 openssl 依赖
CRYPTO_MODE=builtin ANDROID_GATE=0 \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh

# 个人化命名空间（前缀 + per-build 随机后缀）
V6_NS=yourname ANDROID_GATE=0 \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh

# 抗 AI 声明（可选）
AI_GUARD=1 AI_GUARD_OWNER="Your Name" ANDROID_GATE=0 \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh
```

### `V6_NS` 说明

把作者标识"风格化"进变量名，**不破坏 per-build 随机化**：

```
产物里：  yourname_k9x2, yourname_m3p8, ...   ← 每次构建后缀都不同
```

- ✅ 看得出是谁的产物
- ✅ 攻击者无法写固定规则（每次后缀随机）
- ✅ 不参与任何密钥派生
- ✅ 未设置时行为与历史版本**逐字节一致**
- ⚠️ 前缀必须是合法标识符（`[A-Za-z_][A-Za-z0-9_]*`），最长 24 字符

**为什么不做成完全固定的名字**：随机变量名存在的**唯一理由**就是"不固定"。固定 = 给攻击者一个**永久锚点**，一条 `grep` 就能定位密钥链的每一环，并可用跨样本比对反推结构。

---

## 三、混淆前体检（**强烈建议**）

```bash
python3 tools/v6_lint.py your_script.sh
python3 tools/v6_lint.py your_script.sh --strict    # 有问题即 exit 1，可挂 CI
```

**检查项**：

| 级别 | 内容 |
|---|---|
| **ERROR** | `errexit` / `xtrace` / `PS4` / `BASH_XTRACEFD` / `LD_PRELOAD` / builtin 遮蔽 / DEBUG trap |
| WARN | `nounset` / `pipefail` / `shopt` / `IFS` / 提前 `exit` / `exec` |
| INFO | `PATH` / `cd` 相对路径 / 易失败命令行尾 |

> **为什么必须先体检**：这些都会**命中产物的反调试指纹** → 主密钥污染 → **静默 exit、零提示**。

---

## 四、运行期排障

```bash
bash tools/v6_pm_diag.sh
```

逐条列出 6 项会触发密钥污染的条件，**`errexit` 放在首位**（它是"跑几条就停"的最高频原因）。

---

## 五、测试

```bash
# V6 lint 自测（41 项，含变异自检）
python3 tools/v6_lint_test.py

# 回归测试
bash tests/regress.sh

# ISA 端到端集成测试
python3 tools/isa_itest.py
```

### 验证原则

> **唯一可靠的验证是"逐字节对拍"**（原脚本 vs 产物：rc + stdout + stderr）。

混淆系统里"能跑通"和"结果正确"是两件完全不同的事。**静默算错比崩溃危险**——崩溃你会去查，静默算错你会交付一个坏产物。

---

## 六、V7：构建 ELF 封装

```bash
# 基本构建
bash v7/v7_build.sh app.sh out.elf

# VMP 就绪的构建（开启防内联 + 去 NEON）
V7_VMP=1 bash v7/v7_build.sh app.sh out.elf

# per-build 常量随机化（废掉 strings 路标）
V7_RAND_LABEL=1 V7_LABEL_OBF=1 bash v7/v7_build.sh app.sh out.elf
```

### 环境变量速查

| 变量 | 作用 |
|---|---|
| `V7_VMP=1` | 开启 VMP 所需编译开关（= `V7_NOINLINE=1` + `-mgeneral-regs-only`） |
| `V7_NOINLINE=1` | 关键函数不被 `-O2` 内联（VMP 前提） |
| `V7_RAND_LABEL=1` | 每次构建换一组域分离标签 |
| `V7_LABEL_OBF=1` | 标签 XOR 混淆存储（`strings` 也失效） |
| `V7_SELF=1` | 单进程线透明解密激活开关（**基线验证必须注入**） |
| `V7_DIAG=1` | 诊断输出 |

### 退出码

| 码 | 含义 |
|---|---|
| `113` | 反调试拒绝 |
| `114` | 完整性 / MAC 失败 |
| `121` | 裸环境缺工具 |

---

## 七、VMP 对接

见 [`VMP_NOTES.md`](VMP_NOTES.md)。快速版：

```bash
# 1. 用 VMP 就绪的方式构建（会同时产出 .map）
V7_VMP=1 bash v7/v7_build.sh app.sh out.elf

# 2. NEON 体检
python3 tools/vmp_apply.py out.elf --check-neon

# 3. 逐函数验证 + 自动剔除坏函数 + 幸存清单批量保护
python3 tools/vmp_apply.py out.elf --verify --vmpacker /path/to/vmpacker
```

---

## 八、跨架构说明

| 场景 | 注意 |
|---|---|
| x86 宿主构建 aarch64 产物 | 需要交叉工具链；运行时用 `qemu-aarch64-static` |
| **判定解释器可用性** | **不能用 `-x`**！异构 ELF 有 `+x` 位却跑不起来。用 `"$1" -c 'exit 0'` 探针 |
| qemu 下的 `getcwd` 噪音 | 属**模拟器缺陷**，比对前需剔除，否则逐字节比对全部失败 |

---

## 九、构建产物处理顺序（不可颠倒）

```
编译链接
  → 导出符号快照（.map）        ← 必须在加固前
  → VMP 保护（可选）
  → 抹节区头（anti-disassembly）
  → 剔除诊断串
```

> **`.map` 是本地构建资料，勿随发行版分发**（它是"哪里是敏感函数"的地图）。

---

## 十、常见问题

| 症状 | 先查 |
|---|---|
| 产物跑一部分就停 | `v6_lint.py`（`errexit`） |
| 产物静默 exit | `v6_pm_diag.sh`（指纹） |
| 输出乱码 / base64 垃圾 | 变量名撞名（密钥链分叉） |
| rc=113 / 114 / 121 / 132 | 见 [`PITFALLS.md`](PITFALLS.md) 排障速查表 |

完整症状→根因对照见 [`PITFALLS.md`](PITFALLS.md)。
