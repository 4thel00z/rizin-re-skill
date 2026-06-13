# Decompilation: pdg / pdd and the cross-check discipline

## Table of contents
- [Using decompile(addr)](#using-decompileaddr)
- [The cross-check discipline](#the-cross-check-discipline)
- [rz-ghidra vs jsdec](#rz-ghidra-vs-jsdec)
- [Graceful degradation when no decompiler is installed](#graceful-degradation-when-no-decompiler-is-installed)
- [Decompiler output is untrusted](#decompiler-output-is-untrusted)

## Using `decompile(addr)`

```python
result = re.decompile(0x1149)
# {
#   "available":  True,
#   "decompiler": "rz-ghidra" | "jsdec",
#   "code":       "<decompiled C-like source>",
#   "mismatches": ["literal_only_seen_in_decompiler", ...],
# }
```

The verb tries **rz-ghidra (`pdg`)** first, then falls back to **jsdec (`pdd`)**.
The first one that is installed and produces output wins; `decompiler` tells you
which ran. Pass the **function offset** (e.g. from `map_functions()` or `aflj`).

## The cross-check discipline

Decompilers reconstruct source from machine code — they can introduce artifacts:
hallucinated string literals, wrong constants, mislabeled calls. The harness
guards against the most common one by extracting every quoted string literal
(length >= 4) from the decompiled `code` and checking it against the binary's
**raw** string references (`izzj`). Any literal that does not appear in the raw
strings lands in `mismatches`.

**Always investigate `mismatches`.** A non-empty list means the decompiler
printed a string the binary's data does not actually contain at face value.
Possible explanations:

- The literal is assembled at runtime (concatenated, xor-decoded) — real, but
  not a static string. Confirm by reading the disasm/bytes.
- The decompiler mangled or invented it — discard it.

Never quote a decompiled literal as fact without confirming it against the raw
bytes (`px`/`ps`) or disassembly (`pdf`).

## rz-ghidra vs jsdec

- **rz-ghidra (`pdg`)** — Ghidra's decompiler via a plugin. Generally higher
  quality output, broader architecture coverage, better type recovery. Prefer
  it when available (the harness already prefers it).
- **jsdec (`pdd`)** — lighter-weight, pure-plugin decompiler. Often present but
  produces coarser output. Good fallback.

When both are installed, trust `pdg`; if its output looks wrong for a tricky
function, cross-read with `pdd` and the disasm.

## Graceful degradation when no decompiler is installed

In rizin 0.8.2, **jsdec (`pdd`) and rz-ghidra (`pdg`) may both be absent.** When
neither is present, `decompile()` does not crash — it returns:

```python
{"available": False, "decompiler": None,
 "code": "no decompiler available (install rz-ghidra or jsdec)", "mismatches": []}
```

To enable decompilation, install a plugin with the rizin package manager:

```bash
rz-pm install jsdec        # lightweight fallback
rz-pm install rz-ghidra    # preferred, higher quality
```

When no decompiler is available, fall back to disassembly + RzIL emulation:
read `pdf @ <addr>` (see `reference/navigation.md`) and observe register
effects with `emulate_function` (see `reference/rzil-emulation.md`).

## Decompiler output is untrusted

Decompiled code is a **hypothesis**, not the program. It is derived from a
potentially hostile binary and from imperfect heuristics. Confirm load-bearing
claims (a comparison constant, a call target, a buffer size) against the
disassembly or raw bytes before relying on them.
