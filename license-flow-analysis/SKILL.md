---
name: license-flow-analysis
description: Analyses software activation and license verification flows. Locates activation-related literals in a binary, profiles key formats, tests candidate checksum schemes, generates candidates against a local verifier, and diffs two builds to narrow down comparison sites. Use when the user asks about serial number validation, activation logic, trial or expiry handling, machine binding, license key format, or how a program decides whether a key is accepted.
description_zh: 用于 license-flow-analysis 相关工作流。
description_en: Skill for license-flow-analysis workflows.
version: 1.0.0
author: Xiaotao
---

# License / Activation Flow Analysis

All work goes through `scripts/license_tools.py`. Run `--help` first.

## Commands

```bash
python scripts/license_tools.py scan     <file> --min 5
python scripts/license_tools.py probe    "ABCD1-EFGH2-IJKL3"
python scripts/license_tools.py checksum "ABCD1-EFGH2-IJKL3"
python scripts/license_tools.py generate --template "XXXXX-XXXXX" --charset base32 --count 20 --seed 1
python scripts/license_tools.py verify   --verifier verifier.py --codes-file codes.txt
python scripts/license_tools.py bdiff    app_v1.exe app_v2.exe
```

## Workflow

1. **Locate** — `scan` groups candidate literals into activation, trial,
   verdict, crypto, binding, network. Start from whichever group matches the
   behaviour being investigated.
2. **Cross-reference** — carry the literal's address back to code. Needs a
   disassembler; install r2 if missing, then `re_tools.py disasm` around it.
3. **Profile the key** — `probe` reports group sizes, alphabet, and which
   charset it could decode from. `checksum` tests Luhn, sum-mod-N, CRC32, and
   base32 index-sum to see whether a self-check digit exists, which shrinks the
   candidate space.
4. **Build a local verifier** — write `verifier.py` exposing
   `verify(code) -> bool`, then screen candidates with
   `verify --verifier verifier.py`.
5. **Narrow down** — `bdiff` between builds lists differing byte ranges and
   shows both sides, collapsing the search to concrete regions.

## Finding the decision point

- Verdict-group literals ("invalid", "accepted", "thank you") usually sit next
  to the branch that reports the outcome — trace outward from the message
- Failure and success paths typically converge on one return; find the
  conditional jump there
- Network-checked targets: look at the network group plus WinINet / WinHTTP /
  WS2_32 imports
- Machine-bound targets: look at the binding group plus
  `GetVolumeInformation` / `GetAdaptersInfo`-style imports

## Verifier contract

```python
def verify(code: str) -> bool:
    # pure function, no network, no side effects
    ...
```

`verify` loads it via importlib and calls it per candidate. Exit output lists
PASS/fail per code plus a pass count.

## Discipline

- Dry-run patches before writing; keep backups
- Record hashes before and after modification
- Report findings as: literal address → cross-reference → branch location →
  verified by command
