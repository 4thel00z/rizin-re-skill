# JSON command cheat sheet (rizin 0.8.2)

## Table of contents
- [The j-suffixed commands the skill uses](#the-j-suffixed-commands-the-skill-uses)
- [Parsing notes](#parsing-notes)
- [rizin 0.8.x gotchas](#rizin-08x-gotchas)
- [Decompiler plugins may be absent](#decompiler-plugins-may-be-absent)
- [Address validation behavior](#address-validation-behavior)

## The j-suffixed commands the skill uses

Most rizin commands take a `j` suffix to emit JSON. Use `re.cmdj(...)` for these
(it parses the JSON and raises `RizinJSONError` on bad output); use `re.cmd(...)`
for plain text. These are the ones the harness relies on, all verified on
**rizin 0.8.2**:

| Command  | Meaning                                   | Returned by `cmdj` |
|----------|-------------------------------------------|--------------------|
| `ij`     | bin info (arch, bits, type, os)           | object             |
| `aflj`   | analyzed functions (offset, name, size…)  | array of objects   |
| `iij`    | imports (name, plt…)                      | array of objects   |
| `izzj`   | strings — **whole binary** (vaddr, string)| array of objects   |
| `iSj`    | sections (name, size, perm…)              | array of objects   |
| `iej`    | entrypoints (vaddr…)                      | array of objects   |
| `axtj`   | xrefs **to** the current/given address    | array of objects   |
| `axfj`   | xrefs **from** the current/given address  | array of objects   |
| `arj`    | register state                            | object             |

Address-scope any of them with `@ <addr>`, e.g. `axtj @ 0x1149`.

Note the difference between `izj` (strings in data sections only) and **`izzj`
(strings across the whole binary)** — the skill uses `izzj` so it does not miss
strings outside `.data`/`.rodata`.

## Parsing notes

- `cmdj` returns `None`-ish or an empty list when there is nothing to report
  (e.g. `axtj` at an address with no xrefs). The harness guards every call with
  `... or []` / `... or {}`; do the same in your own raw usage.
- A command that has no JSON output (or that you ran without the `j` suffix)
  returns plain text — calling `cmdj` on it raises `RizinJSONError`. Use `cmd`
  for text commands like `pdf`, `afn`, `CC`, `aezse`.

## rizin 0.8.x gotchas

- **`?e` (echo) was REMOVED in rizin 0.8.x.** Use the plain `echo` command
  instead if you need to print a literal line, e.g. `re.cmd("echo hello")`.
  Any older recipe using `?e` will fail on 0.8.2.

## Decompiler plugins may be absent

`jsdec` (`pdd`) and `rz-ghidra` (`pdg`) are **not guaranteed to be installed** on
rizin 0.8.2. When neither is present, `decompile()` degrades to
`{"available": False, ...}` rather than erroring (see `reference/decompilation.md`).
Install one with the package manager to enable decompilation:

```bash
rz-pm install jsdec        # lightweight
rz-pm install rz-ghidra    # preferred
```

## Address validation behavior

When you disassemble at a bad address, rizin 0.8.2 does **not** raise — it prints
a bare token. Specifically, `pi 1 @ <addr>` at an unmapped or misaligned address
prints `unaligned` or `invalid` instead of a mnemonic. The `annotate` verb relies
on exactly this: it treats those tokens as "address does not exist" and refuses
the whole plan (see `reference/annotation.md`). If you do your own address
checks, look for these tokens rather than expecting an exception.
