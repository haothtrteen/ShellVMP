# ShellVMP

**Turn a shell script into a self-protecting artifact.** Two independently usable layers:

- **V6** — A pure-shell script obfuscator: block encryption + execution-state key binding + skip-chain key derivation + batch-level self-modification. Zero external dependencies (`aes` mode needs openssl; `builtin` mode is pure shell/awk).
- **V7** — An ELF wrapper layer: anti-debugging + anti-memory-read + streaming decryption straight into the interpreter. The full plaintext never exists on disk.
- **V7-ISA** — Interpreter-modification layer (PoC): tokenizes command names / keywords / variable names so the artifact on disk is just a stream of random tokens.

> **Platform**: **not tied to any platform.** Artifacts are ELF binaries or plain scripts —
> they run **anywhere Linux/ELF runs**: Android, desktop Linux, servers, containers, embedded.
> **Script sources**: bash is native; dash / POSIX / zsh are **converted to bash** and fed into
> the bash line; mksh has its own second packaging path. **You do not need to modify every
> interpreter** — see [`docs/SHELL_TARGETS.md`](docs/SHELL_TARGETS.md) §0 (Chinese).

> The goal is not "hide it deeper" — it's **changing the attack surface**: no plaintext on disk,
> the runtime plaintext window as short and bounded as possible, and critical logic turned into
> virtual instructions that can't be statically analyzed.

> **📖 Detailed documentation is in Chinese.** This file covers the essentials for an
> English-speaking audience. For the full design docs, threat model, build guides, and
> the honest "what got broken and how" list, see [`docs/`](docs/) — those are written
> in Chinese and are the project's primary documentation.

---

## Table of contents

- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Which line should you use?](#which-line-should-you-use)
- [Why shell is the hardest language to protect](#why-shell-is-the-hardest-language-to-protect)
- [Honest security boundaries](#honest-security-boundaries)
- [License](#license)
- [Documentation](#documentation)

---

## How it works

```
┌─────────────────────────────────────────────────────────────┐
│  Your script (app.sh)  ── plaintext, readable by anyone     │
└────────────────────────┬────────────────────────────────────┘
                         │
              ┌──────────▼──────────┐
              │   V6  Obfuscator    │  Pure shell
              │  ─────────────────  │
              │  blocks → encrypt   │  · each block's ciphertext is independent
              │  → bind → chain     │  · execution state ($?/$_/cwd) mixed into key chain
              │  + decoys + junk    │  · jump chain references block N-7 → must run from start
              └──────────┬──────────┘  · batch-level self-modification (re-encrypt after decrypt)
                         │
                         ▼
                  Skeleton (encrypted shell script)
                         │
              ┌──────────▼──────────┐
              │   V7  ELF wrapper   │  C
              │  ─────────────────  │
              │  scrypt-like KDF    │  · payload appended to ELF tail
              │  Encrypt-then-MAC   │  · parent decrypts by block → pipe → child
              │  pipe streaming     │  · plaintext written then wiped, never hits disk
              └──────────┬──────────┘
                         │
              ┌──────────▼──────────┐
              │   V7-ISA tokenize   │  Modified interpreter
              │  ─────────────────  │
              │  commands/keywords  │  · L1 builtin / L2 external
              │  → random aliases   │  · L3 keywords / L4 vars + paths
              └──────────┬──────────┘  · L6 string literals (ciphertext-resident)
                         ▼
                    Final artifact (ELF)
              `strings` yields nothing but random tokens
```

---

## Quick start

### Minimal: V6 obfuscation

```bash
git clone https://github.com/<you>/ShellVMP.git
cd ShellVMP

# Obfuscate a script
ANDROID_GATE=0 bash v6/shell_script_obfuscator_v6.sh examples/demo_app.sh demo.protected.sh

# Run it
bash demo.protected.sh
```

`ANDROID_GATE=0` is for testing outside Android; by default the Android environment gate is on
(non-Android environments are silently refused).

> ⚠️ **The gate is an optional anti-analysis switch, not a platform restriction.** Its purpose
> is to make artifacts silently refuse to run in environments they *shouldn't* run in (raising
> sandbox-analysis cost). It does **not** mean the project is Android-only. On desktop /
> server / containers, just add `ANDROID_GATE=0` — the same practice applies on **every** platform.

### Common switches

```bash
# Strong obfuscation: junk blocks + decoys
JUNK_LEVEL=3 DECOY_LEVEL=2 \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh

# Key separation: artifact requires a passphrase; master key not stored in artifact
PASSKEY_MODE=1 PASSKEY_COUNT=3 \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh

# Zero openssl dependency (minimal environments)
CRYPTO_MODE=builtin \
  bash v6/shell_script_obfuscator_v6.sh in.sh out.sh
```

### Pre-flight check (recommended)

```bash
python3 tools/v6_lint.py your_script.sh          # static compatibility check
python3 tools/v6_lint.py your_script.sh --strict # exit 1 on issues (CI-friendly)
```

> **Why the check matters**: a host shell's `errexit`, `set -x`, modified `PS4`, or
> redefined builtins will **trip the artifact's anti-debug fingerprint** → master key
> poisoning → **silent exit with no message**. `v6_lint.py` catches these before you obfuscate.

### Minimal V7 (both lines)

```bash
# bash line
V7_MODE=bash V7_BASH_BIN=/path/to/modified-bash ANDROID_GATE=0 \
  bash v7/v7_build.sh your_script.sh app.bash
V7_SELF=1 ./app.bash /dev/null

# mksh line (builds the modified interpreter from source)
V7_MODE=mksh V7_MKSH_SRC=./mksh-src ANDROID_GATE=0 \
  bash v7/v7_build.sh your_script.sh app.mksh
V7_SELF=1 ./app.mksh /dev/null
```

Add `V7_OUTER_PASS='at-least-8-chars'` to require a passphrase
(omit it for **offline distribution mode** — no passphrase at runtime).

> **Two traps that bite everyone** (see [`docs/USAGE.md`](docs/USAGE.md) §4, Chinese):
>
> 1. **Running requires `V7_SELF=1` plus one argv file argument** (convention: `/dev/null`).
>    Missing either → **silent zero output**, symptomatically identical to a decryption
>    failure. Easy to misdiagnose. The artifact is an ELF — run `./app.bash` **directly**,
>    not `bash app.bash`.
> 2. **Slow machines + default passphrase params can give `rc=113`** (the anti-debug timing
>    window gets hit by KDF latency). Add `V7_SCRYPT_N=16384` when debugging on a desktop,
>    or use offline distribution mode.

---

## Which line should you use?

| Line | Entry point | Artifact | Tokenization | Host dependency | Status |
|---|---|---|---|---|---|
| **Pure-script** (fastest) | `v6/shell_script_obfuscator_v6.sh` | obfuscated `.sh` | ❌ | host needs bash **or** mksh | ✅ stable |
| **bash line** (primary) | `v7/v7_build.sh` | modified bash binary | ✅ L1–L6 | self-contained | ✅ production-ready |
| **mksh line** (second path) | `v7/v7_build.sh` (`V7_MODE=mksh`) | modified mksh binary | ✅ L1–L6 | self-contained | ⚠️ packaging works (C1/C2/C3 pass); inner-passphrase mode pending |

| Your situation | Choose |
|---|---|
| Just want to stop casual source leakage | **Pure-script** (zero build, one command) |
| Want maximum protection, can accept a multi-MB bundled interpreter | **bash line** (the **primary** line — handles all script sources) |
| Want a smaller artifact (mksh ~30k LoC vs bash ~1.5M) / targeting Android devices | **mksh line** (the **second packaging path**) |
| Not sure | Start with pure-script, then move to bash line |

> **Why only bash and mksh?** The early assumption was "the project is useless unless we
> modify every interpreter". **That premise doesn't hold.** The correct path is to
> **convert scripts from any dialect into bash first**, then feed them to the bash line —
> community translation tools plus our convergence audit
> ([`docs/DASH_SYNTAX_AUDIT.md`](docs/DASH_SYNTAX_AUDIT.md), Chinese) handle this.
> Interpreter modification is the **most expensive** link in the chain, so we minimize it:
> **bash as primary, mksh as the second packaging path, no new lines beyond that.**

---

## Why shell is the hardest language to protect

| Property | Consequence |
|---|---|
| **No compile time** | Unlike C, nothing can be computed at build time — all key derivation happens at runtime |
| **Process is the boundary** | Every `$( )` / `\|` can leak keys or plaintext (`/proc/pid/cmdline`) |
| **Everything is a string** | Variables, functions, commands are all strings; no type system to pin down semantics |
| **Builtins are privileged** | An attacker who redefines `eval` / `type` can hijack your entire execution chain |

**The flip side is a unique advantage**: shell has no binary, so **every line can be ciphertext**
— a granularity that compiled languages simply don't have.

---

## Honest security boundaries

> **This is the most important section of the project. Any script protection claiming to be
> "uncrackable" is a scam.**

### What it stops

- ✅ **Casual source reading** — `cat` no longer tells you the logic
- ✅ **Static bulk scraping** (crawlers / automated de-obfuscation)
- ✅ **On-disk plaintext analysis** (no complete plaintext exists on disk)
- ✅ **Non-root memory reads** (`PR_SET_DUMPABLE=0` + seccomp-BPF — the one deterministic measure)
- ✅ **Debuggers / injection** (TracerPid / frida trace scanning / `LD_PRELOAD`)

### What it does not stop

| Attacker capability | Reality |
|---|---|
| **root privileges** | Can read `/proc/pid/mem` (`PROT_NONE` doesn't stop it — it goes via `get_user_pages`, which doesn't check page-table permissions). **We tested this and it broke our assumption** |
| **Long enough runtime observation** | The interpreter eventually has to consume plaintext. All you can do is **shorten the window + dilute the signal-to-noise ratio** |
| **Patient manual reverse engineering** | All obfuscation "raises cost", never "removes possibility". The goal is "cost > payoff" |
| **AI-assisted analysis** | The anti-AI declaration (`AI_GUARD=1`) blocks some of it, but is **not a technical defense** |

### In one sentence

> **Overall strength ≈ weakest component, and all components share a single root of trust
> (one dump exposes everything).** We don't promise "uncrackable" — we promise
> "**reverse-engineering cost > value of your script**".

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) (Chinese).

---

## License

**Dual licensing — pick one, you don't have to satisfy both.**

| Path | License | Applies to | Cost |
|---|---|---|---|
| **Open source** | **[AGPLv3](LICENSE)** | Personal / internal use / open-source projects / academic | **Free**, but you must publish the full modified source when distributing or offering it as a network service |
| **Commercial** | **[LICENSE.COMMERCIAL](LICENSE.COMMERCIAL)** | Closed-source commercial use, or running SaaS without open-sourcing | Requires written authorization from the copyright holder |

> **In one sentence**: if you're willing to **open-source your modifications**, commercial use
> is free. You only need to buy a license if you want to **stay closed-source while shipping commercially**.

**Copyright holder**: 皓thirteen (GitHub: [@haothtrteen](https://github.com/haothtrteen)) · `2557976190@qq.com`
Commercial licensing inquiries via email, subject prefixed with `[ShellVMP Commercial]`.
See **[`LICENSE.COMMERCIAL`](LICENSE.COMMERCIAL)** (Chinese) for details.

### Attribution is required either way

**Hard requirement**: any form of distribution (open or closed source, modified or not,
source or binary) must retain the **original copyright and license notices** in both code
and artifact. See `LICENSE` sections 4 and 5.

### Third-party components are not covered by this license

| Directory / component | License | Obligation |
|---|---|---|
| `v7/bash_poc/` | **GPLv3+** | Derived from GNU bash. Distributing an artifact with a bundled modified bash → **you must provide the complete corresponding source**. **A commercial license cannot waive this** — that right belongs to bash, not us. |
| `v7/mksh_poc/` | **MirOS** | Derived from mksh. Lighter obligation: retain copyright and license notices; **no source disclosure required**. |
| `sh-hook/` | AGPLv3 | Sub-project of this repo, same terms. |
| **VMPacker** (external tool) | **AGPL-3.0** | Called by `tools/vmp_apply.py` via `subprocess` — **a toolchain dependency, not code integration**. This repo contains none of its source and performs no linking. Independently maintained by a third party; **users must obtain it themselves**. |

> **Want to distribute artifacts fully closed-source?** Use the **mksh line** (MirOS, no
> source disclosure) rather than the bash line. Detailed accounting in
> [`docs/OPEN_SOURCE_SCOPE.md`](docs/OPEN_SOURCE_SCOPE.md) (Chinese).

**Disclaimer**: this project is **defensive security research**. Users should only apply it
to code they **own or are authorized to protect**. The author accepts no responsibility for misuse.

---

## Documentation

Full documentation is in Chinese — which is where the project's depth lives. Highlights:

| Topic | Doc |
|---|---|
| **Usage guide: build, switches, caveats** | [`docs/USAGE.md`](docs/USAGE.md) |
| **How this was built through trial and error** | [`docs/JOURNEY.md`](docs/JOURNEY.md) |
| Threat model & capability boundaries | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) |
| **Pitfalls, indexed by symptom** | [`docs/PITFALLS.md`](docs/PITFALLS.md) |
| Architecture & crypto design | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| Build guide (bash line / mksh line) | [`docs/BUILD.md`](docs/BUILD.md) · [`docs/BUILD_MKSH.md`](docs/BUILD_MKSH.md) |
| What's open, what's reserved, and why | [`docs/OPEN_SOURCE_SCOPE.md`](docs/OPEN_SOURCE_SCOPE.md) |
| Historical source archives (v0 → v7) | [`docs/HISTORY/`](docs/HISTORY/README.md) |

### The three worth reading first

If you only have ten minutes:

1. **[`docs/JOURNEY.md`](docs/JOURNEY.md)** — the full v0→v6 trial-and-error record. Every
   section is "I thought this would work → testing proved me wrong → changed it to this".
   **The failure modes carry more information than the successes.**
2. **[`docs/PITFALLS.md`](docs/PITFALLS.md)** — pitfalls indexed by symptom, including six
   "I assumed X, testing proved otherwise" entries.
3. **[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)** — the honest capability boundary.
   **Any script protection claiming to be "uncrackable" is a lie.**

---

Copyright (C) 2026 haothtrteen <2557976190@qq.com>
