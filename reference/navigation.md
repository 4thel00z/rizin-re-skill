# Navigation: disasm, xrefs, call graph, data

## Table of contents
- [Listing functions](#listing-functions)
- [Seeking](#seeking)
- [Disassembling a function](#disassembling-a-function)
- [Cross-references (xrefs)](#cross-references-xrefs)
- [Call graph](#call-graph)
- [Reading data and strings at an address](#reading-data-and-strings-at-an-address)
- [Workflow: chasing a lead](#workflow-chasing-a-lead)

All recipes use the raw escape hatch: `re.cmd(...)` for text, `re.cmdj(...)` for
JSON. Verified on rizin 0.8.2.

## Listing functions

- `re.cmd("afl")` — human-readable function list (addr, size, name).
- `re.cmdj("aflj")` — same as JSON; each entry has `offset`, `name`, `size`,
  `nbbs` (basic-block count), and more. Prefer `map_functions()` for a ranked,
  truncated view; use `aflj` when you need raw fields.

## Seeking

- `re.cmd(f"s {addr}")` — set the current offset (seek) to `addr`. Many commands
  operate on the current offset unless you append `@ <addr>`.
- `re.cmd("s")` — print the current offset.
- You can pass `@ <addr>` to most commands to run them at a temporary offset
  without moving the seek, e.g. `pdf @ 0x1149`.

## Disassembling a function

- `re.cmd(f"pdf @ {addr}")` — disassemble the whole function at `addr`
  (the canonical "show me this function" command).
- `re.cmd(f"pd {n} @ {addr}")` — disassemble `n` instructions from `addr`.
- `re.cmd(f"pi {n} @ {addr}")` — print just `n` instruction mnemonics (no
  addresses/bytes). Note: at an unmapped/unaligned address rizin 0.8.2 prints
  `invalid` or `unaligned` — the harness uses exactly this to validate addresses.
- `re.cmdj(f"pdfj @ {addr}")` — function disassembly as JSON (ops array with
  `offset`, `opcode`, `type`, `esil`, etc.) when you need to parse it.

## Cross-references (xrefs)

- `re.cmdj(f"axtj @ {addr}")` — xrefs **to** `addr` (who calls/references it).
  Each entry has `from` (the referencing address), `type` (`CALL`, `DATA`, ...).
- `re.cmdj(f"axfj @ {addr}")` — xrefs **from** `addr` (what this code references
  outward — its callees and data reads).
- `map_functions()` already counts both (`xrefs` = axt count, `calls` = axf count)
  per function; drop to raw `axtj`/`axfj` when you need the actual edges.

## Call graph

- `re.cmdj(f"agj @ {addr}")` — the call/flow graph rooted at `addr` as JSON
  (nodes + edges). Useful for understanding control flow within a function.
- `re.cmd(f"agf @ {addr}")` — ASCII function graph for quick visual inspection.
- `re.cmd("agC")` — global call graph (can be large; prefer scoping to a function).

## Reading data and strings at an address

- `re.cmdj(f"pxj {n} @ {addr}")` — `n` bytes of hex as a JSON array of ints.
- `re.cmd(f"px {n} @ {addr}")` — classic hexdump.
- `re.cmdj(f"psj @ {addr}")` — the string at `addr` as JSON (`{string, ...}`).
- `re.cmd(f"ps @ {addr}")` — print the string at `addr` as text.

## Workflow: chasing a lead

1. From triage, you have an interesting address (a string, an import PLT, an
   entrypoint).
2. `axtj @ <addr>` — find referencing sites.
3. For each `from`, seek into the containing function: `re.cmd(f"s {from}")`,
   then `re.cmd("pdf")` (or `pdf @ <fn_offset>`).
4. Read the disasm; identify the function's role.
5. `decompile(fn_offset)` for a higher-level view (see `reference/decompilation.md`),
   then `annotate(...)` to record what you learned.
6. Always cite the address in your conclusions so they can be re-verified.
