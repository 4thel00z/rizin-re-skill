# rizin-re

Hand Claude a binary and ask what it does. This skill gives it a live
[rizin](https://rizin.re) session to reason in — triage, function maps,
cross-references, decompilation, emulation, and annotation — so the analysis
builds up across steps instead of evaporating between one-shot commands.

The design is hybrid. Operations that must stay safe or deterministic are typed
verbs in `harness.py`; open-ended exploration runs through a raw `cmd`/`cmdj`
escape hatch, guided by the recipes in `reference/*.md`. Untrusted input stays
untrusted: static analysis is the default, RzIL emulation never runs native
code, and the debugger is refused unless you opt in (and refused outright on
macOS).

Tested against **rizin 0.8.2**.

## Prerequisites

- **rizin >= 0.8** on `PATH` (developed and tested on 0.8.2).
- **Python >= 3.9**.
- The **`rzpipe`** Python package (the modernized `RizinSession` client this
  skill dogfoods).
- Optional, for decompilation: a decompiler plugin. Neither is guaranteed on
  0.8.2. **rz-ghidra is preferred** — it gives higher-quality output and its
  `pdgj` JSON lets `decompile()` return an `annotations` list mapping decompiled
  tokens to binary addresses. On macOS arm64 + Homebrew, rz-ghidra must be built
  from source (see `reference/decompilation.md` for the exact cmake recipe).
  jsdec is the lighter, no-build alternative:
  ```bash
  rz-pm install jsdec        # lightweight fallback (pdd / pddj)
  # rz-ghidra: build from source — see reference/decompilation.md
  ```
  Without a plugin, `decompile()` degrades to `available: False` instead of
  failing.

## Install

1. Install the `rzpipe` package (editable, from the rz-pipe repo):
   ```bash
   pip install -e /path/to/rz-pipe/python
   python3 -c "import rzpipe; print('ok')"
   ```
2. Make the skill discoverable by Claude Code — symlink (or copy) the skill
   directory into your skills folder:
   ```bash
   mkdir -p ~/.claude/skills
   ln -sfn "$(pwd)" ~/.claude/skills/rizin-re
   ```

## Usage

```python
from harness import RizinRE

with RizinRE("/path/to/binary") as re:   # spawns rizin, runs `aaa`
    t = re.triage_binary()               # arch, imports, strings, sections, entrypoint, fn count
    top = re.map_functions()             # functions ranked by triage score
    code = re.decompile(top[0]["offset"])  # decompile the highest-scoring function
    re.annotate([{"kind": "rename", "addr": top[0]["offset"], "name": "main_logic"}])
```

See `SKILL.md` for the full verb index and `reference/*.md` for recipes.

## Safety tiers

- **Tier 0 — static (default).** `triage_binary`, `map_functions`, `decompile`,
  navigation. Never executes the target.
- **Tier 1 — RzIL emulation.** `emulate_function` — RzIL only, no native
  execution; safe on untrusted code.
- **Tier 2 — native debug.** `debug_session` — **refused** unless
  `RIZIN_RE_SANDBOX_CONFIRMED=1` is set **and** `human_ack=True` is passed, and
  it is **refused outright on macOS** (Firecracker/gVisor are Linux-only). See
  `reference/debug-sandbox.md`.

All strings and metadata read from a binary are treated as untrusted input.
Every raw `cmd`/`cmdj` call is logged for audit.

## Running the tests

```bash
python3 -m pytest tests/
```

The suite runs against a small committed fixture binary (`tests/fixture`, built
from `tests/fixture.c`) with a known function, string, and import, plus the
sandbox-gate tests. Build the fixture first if it is missing:

```bash
cc -O0 -o tests/fixture tests/fixture.c
```

## Spec

Design and decisions are recorded in the spec, kept alongside the repos at
`../docs/superpowers/specs/2026-06-13-rizin-re-skill-design.md`.

## License

MIT — see `LICENSE`.
