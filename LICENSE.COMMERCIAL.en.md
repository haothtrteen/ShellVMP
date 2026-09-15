# Commercial Licensing

ShellVMP is **dual-licensed**:

1. **Open source**: GNU Affero General Public License v3.0 (see [`LICENSE`](LICENSE)) —
   free of charge, but carries **strong copyleft** obligations (see "The open-source path" below).
2. **Commercial**: granted separately by the copyright holder, permitting **closed-source
   commercial use** (see "The commercial path" below).

**You choose one — you do not have to satisfy both.**

> **Copyright holder**
> 皓thirteen (GitHub: [@haothtrteen](https://github.com/haothtrteen))
> Email: **2557976190@qq.com**
>
> For commercial licensing, please use **email** with a subject line beginning
> `[ShellVMP Commercial]`.

---

## 1. When you do NOT need a commercial license

The following are **free under AGPLv3 — no need to contact us**:

| Your use case | Free? | Condition |
|---|---|---|
| Personal use, learning, research, experimentation | ✅ Yes | Comply with AGPLv3 |
| Internal company use (no external distribution, no public network service) | ✅ Yes | Comply with AGPLv3 |
| Use in an open-source project (yours also licensed under an AGPLv3-compatible license) | ✅ Yes | **Publish your entire modified source** |
| Educational institutions, charities, public research, government agencies | ✅ Yes | Comply with AGPLv3 |
| Distributing artifacts to your own customers | ✅ Yes | **Only if** your overall service satisfies AGPLv3 (i.e. you are open-source too) |

**In one sentence**: as long as you are willing to **open-source your modifications**,
commercial use is free.

---

## 2. When you DO need a commercial license

In the following cases AGPLv3 **does not grant** you the rights you need:

| Your use case | Why AGPLv3 isn't enough |
|---|---|
| **Closed-source commercial use**: integrating a modified version into a closed-source product and distributing it | AGPLv3 requires you to open-source the entire modified source |
| **SaaS / network service**: letting users access your modified version over a network | **AGPLv3 Section 13** requires providing those users with the complete source |
| Wanting to **avoid AGPLv3's full obligations** while staying closed-source | AGPLv3's obligations are mandatory and non-negotiable |
| Needing **commercial warranty / technical support / liability** | AGPLv3 Sections 15–16 **explicitly provide no warranty** |

A commercial license grants you the right to **waive AGPLv3 obligations within an agreed
scope** (you may keep it closed-source and operate network services without open-sourcing).
The specific scope, term, fees, territory, and support level are set by a **signed written
agreement between the parties**.

---

## 3. The open-source path: what AGPLv3 requires of you

If you choose AGPLv3, your core obligations are:

1. **Distribution triggers disclosure**: when you distribute a modified version (binary or
   source), you must provide recipients with the **complete corresponding source**
   (including your modifications and build scripts).
2. **Network service triggers disclosure (Section 13)**: if you let users interact with a
   modified version over a computer network, you must provide **those users** with the
   complete corresponding source.
3. **Retain notices**: you must retain copyright and license notices and include the full
   AGPLv3 text.
4. **Same license**: your modified version must be licensed under AGPLv3 (or a compatible
   license), with no additional restrictions.

---

## 4. Note for contributors

For **dual licensing** to be legally valid, this project requires **copyright concentration**.
Therefore:

> **Submitting a contribution (Pull Request / patch) to this repository means you agree to
> assign the copyright in that contribution (or sufficient rights to support commercial
> licensing) to the copyright holder, enabling them to distribute your contribution under
> both AGPLv3 and the commercial license.**

If your organization objects to this, please contact us before submitting.

---

## 5. Third-party components are not governed by this license

This project's license **covers only its own code**. The following components' licenses are
**mandatorily inherited from upstream**, cannot be changed by the copyright holder, and
**are not covered by a commercial license**:

| Directory / component | License | Notes |
|---|---|---|
| `v7/bash_poc/` | **GPLv3+** | Derived from GNU bash. When distributing an artifact containing a modified bash binary, you must provide the complete corresponding source — **this is a hard requirement of bash and cannot be waived by purchasing a commercial license**. |
| `v7/mksh_poc/` | **MirOS** | Derived from mksh. Lighter obligation: retain copyright and license notices. |
| `sh-hook/` | AGPLv3 | Sub-project of this repository, consistent with it. |
| **VMPacker** (external tool) | **AGPL-3.0** | Invoked by `tools/vmp_apply.py` via `subprocess`. This is a **toolchain dependency, not code integration** — this repository contains none of its source code and does not link against it. VMPacker is independently maintained by a third party and **must be obtained separately by the user** (see [`docs/VMP_NOTES.md`](docs/VMP_NOTES.md)). If its VM interpreter stub is injected into an artifact, that artifact contains an AGPL component; AGPL does not restrict use of the protected output. |

> **Practical tip**: if your commercial scenario requires **fully closed-source distribution
> of artifacts**, consider the **mksh line** (MirOS — no source disclosure required) rather
> than the bash line. See section 3 of
> [`docs/OPEN_SOURCE_SCOPE.md`](docs/OPEN_SOURCE_SCOPE.md) (Chinese).

---

## 6. Disclaimer

This project is **defensive security research**. Users should apply it only to code they
**own or are authorized to protect**. The author accepts no responsibility for misuse.

> This document is a **licensing explanation** and does not constitute legal advice.
> Formal commercial engagements are governed by the signed agreement between the parties;
> consult a lawyer where significant interests are at stake.

---

Copyright (C) 2026 haothtrteen <2557976190@qq.com>
