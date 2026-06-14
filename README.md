<h1 align="center">rizin-re</h1>

<p align="center">
  <strong>Hand Claude a binary, ask what it does</strong>
</p>

---

## Motivation

A Claude Code skill for understanding binaries. It gives Claude a live
[rizin](https://rizin.re) session to reason in — triage, function maps,
cross-references, decompilation, emulation, annotation — so analysis builds up
across steps instead of evaporating between one-shot commands.

Safety-critical work is typed verbs in `harness.py`; exploration runs through a
raw `cmd`/`cmdj` escape hatch, guided by `reference/*.md`. Untrusted input stays
untrusted: static analysis by default, RzIL emulation never runs native code,
the debugger is opt-in only (and refused on macOS).

## Installation

Needs **rizin ≥ 0.8** on `PATH` (tested on 0.8.2) and **Python ≥ 3.9**.

```bash
pip install -e /path/to/rz-pipe/python      # the rzpipe client this skill drives
ln -sfn "$(pwd)" ~/.claude/skills/rizin-re  # let Claude Code discover the skill
```

Decompilation is optional. **rz-ghidra** is preferred — its `pdgj` JSON gives
`decompile()` an `annotations` map — and builds from source; see
[reference/decompilation.md](reference/decompilation.md). `rz-pm install jsdec`
is the lighter alternative. Without either, `decompile()` reports
`available: False` instead of failing.

## Usage

```python
from harness import RizinRE

with RizinRE("/path/to/binary") as re:    # spawns rizin, runs `aaa`
    t = re.triage_binary()                # arch, imports, strings, sections, entrypoint
    top = re.map_functions()              # functions ranked by triage score
    code = re.decompile(top[0]["offset"])
    re.annotate([{"kind": "rename", "addr": top[0]["offset"], "name": "main_logic"}])
```

See [SKILL.md](SKILL.md) for the full verb index and `reference/*.md` for recipes.

## Safety tiers

- **Tier 0 — static (default).** `triage_binary`, `map_functions`, `decompile`, navigation. Never executes the target.
- **Tier 1 — RzIL emulation.** `emulate_function` — emulated only, no native execution; safe on untrusted code.
- **Tier 2 — native debug.** `debug_session` — refused unless `RIZIN_RE_SANDBOX_CONFIRMED=1` **and** `human_ack=True`, and refused outright on macOS. See [reference/debug-sandbox.md](reference/debug-sandbox.md).

## Tests

```bash
cc -O0 -o tests/fixture tests/fixture.c   # build the fixture if missing
python3 -m pytest tests/
```

## License

MIT — see [LICENSE](LICENSE).
