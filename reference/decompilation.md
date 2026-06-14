# Decompilation: pdg / pdd and the cross-check discipline

## Table of contents
- [Using decompile(addr)](#using-decompileaddr)
- [The cross-check discipline](#the-cross-check-discipline)
- [rz-ghidra vs jsdec](#rz-ghidra-vs-jsdec)
- [Installing rz-ghidra (build from source)](#installing-rz-ghidra-build-from-source)
- [Graceful degradation when no decompiler is installed](#graceful-degradation-when-no-decompiler-is-installed)
- [Decompiler output is untrusted](#decompiler-output-is-untrusted)

## Using `decompile(addr)`

```python
result = re.decompile(0x1149)
# {
#   "available":   True,
#   "decompiler":  "rz-ghidra" | "jsdec" | None,
#   "code":        "<decompiled C-like source>",
#   "annotations": [{"start": 1, "end": 4, "type": "offset", "offset": 4294968416}, ...],
#   "mismatches":  ["literal_only_seen_in_decompiler", ...],
# }
```

The `annotations` list comes from rz-ghidra's `pdgj` JSON output. Each entry
maps a character range `[start, end)` in `code` to metadata — most commonly
`{"type": "offset", "offset": <addr>}` which ties a token in the decompiled
source back to a binary address. This lets callers correlate decompiled tokens
to disassembly addresses precisely. `annotations` is `[]` when the text fallback
path is used (rz-ghidra absent, or `pdgj` returned no annotation data) or when
jsdec is the active decompiler.

The verb preference order is:
1. **rz-ghidra `pdgj`** (structured JSON — fills both `code` and `annotations`)
2. **rz-ghidra `pdg`** (text fallback — `annotations: []`)
3. **jsdec `pddj`** (structured JSON — `annotations: []`)
4. **jsdec `pdd`** (text fallback — `annotations: []`)
5. `available: False` if no decompiler is installed

`decompiler` in the result tells you which plugin ran. Pass the **function
offset** (e.g. from `map_functions()` or `aflj`).

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

- **rz-ghidra (`pdgj`/`pdg`)** — Ghidra's decompiler via a native plugin.
  Generally higher quality output, broader architecture coverage, better type
  recovery. **Preferred.** The harness always tries rz-ghidra first and uses
  `pdgj` JSON to populate both `code` and `annotations`.
- **jsdec (`pddj`/`pdd`)** — lighter-weight, pure-plugin decompiler. Often
  present but produces coarser output. Good fallback when rz-ghidra is not
  installed.

When both are installed, trust rz-ghidra; if its output looks wrong for a
tricky function, cross-read with jsdec and the disasm.

## Installing rz-ghidra (build from source)

`rz-pm install rz-ghidra` does not work reliably on all platforms. On **macOS
arm64 with Homebrew rizin 0.8.2**, build from source using the recipe below.
Expect the build to take **10–20 minutes** — it compiles the full Ghidra SLEIGH
C++ backend.

### Prerequisites

- Xcode Command Line Tools (`xcode-select --install`)
- `cmake` (Homebrew: `brew install cmake`)
- rizin 0.8.x (Homebrew: `brew install rizin`)
- Homebrew `openssl@3` and `zlib` (both keg-only; installed automatically as
  rizin dependencies but NOT on the default header search paths)

### Build and install

```bash
# 1. Put keg-only libs on pkg-config's path (required — rizin's headers need them)
export PKG_CONFIG_PATH="/opt/homebrew/opt/rizin/lib/pkgconfig:/opt/homebrew/opt/zlib/lib/pkgconfig:/opt/homebrew/opt/openssl@3/lib/pkgconfig"

# 2. Clone rz-ghidra at the matching version tag
git clone --recurse-submodules https://github.com/rizinorg/rz-ghidra /tmp/rz-ghidra-build
cd /tmp/rz-ghidra-build
git checkout v0.8.0                       # must match the rizin 0.8.x line
git submodule update --init --recursive

# 3. Configure
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="$HOME/.local" \
      -DBUILD_CUTTER_PLUGIN=OFF \
      -DCMAKE_PREFIX_PATH="$(brew --prefix)" \
      -DCMAKE_C_FLAGS="-I/opt/homebrew/opt/openssl@3/include" \
      -DCMAKE_CXX_FLAGS="-I/opt/homebrew/opt/openssl@3/include" \
      ..

# 4. Build (~10–20 min)
cmake --build . -j "$(sysctl -n hw.ncpu)"

# 5. Install
cmake --install .
```

**Why the `-DCMAKE_C_FLAGS` / `-DCMAKE_CXX_FLAGS` flags?** rizin's public
header `rz_util.h` does `#include <openssl/bn.h>`. Homebrew's `openssl@3` is
keg-only, so its include directory is not on the default compiler search path.
Without those flags the build fails with `fatal error: 'openssl/bn.h' file not
found`.

### What gets installed

`cmake --install .` places three dynamic libraries and the SLEIGH spec directory
into `~/.local/lib/rizin/plugins/`:

```
~/.local/lib/rizin/plugins/core_ghidra.dylib
~/.local/lib/rizin/plugins/asm_ghidra.dylib
~/.local/lib/rizin/plugins/analysis_ghidra.dylib
~/.local/lib/rizin/plugins/rz_ghidra_sleigh/   (architecture spec files)
```

### Plugin load mechanism

rizin scans `~/.local/lib/rizin/plugins` **by default** — no extra environment
variables are needed after a successful `cmake --install`. Verify the plugin
loads:

```bash
rizin -qc 'Lc' /bin/ls | grep -i ghidra        # should list core_ghidra
rizin -qc 'aa; pdgj @ main' /bin/ls            # should print JSON {"code":...,"annotations":[...]}
```

**Fallback:** if on some setup the plugin does NOT auto-load, export:

```bash
export RZ_USER_PLUGINS="$HOME/.local/lib/rizin/plugins"
```

Because the skill's harness spawns rizin via `RizinSession` which **inherits
the parent process environment**, this variable must be exported in the shell
that launches Claude Code / the harness — not set inside Python.

## Graceful degradation when no decompiler is installed

In rizin 0.8.2, **jsdec (`pdd`) and rz-ghidra (`pdg`) may both be absent.**
When neither is present, `decompile()` does not crash — it returns:

```python
{"available": False, "decompiler": None,
 "code": "no decompiler available (install rz-ghidra or jsdec)",
 "annotations": [], "mismatches": []}
```

To enable decompilation:

```bash
# Lighter, no-build option:
rz-pm install jsdec        # provides pdd / pddj

# Preferred, build from source (see "Installing rz-ghidra" above):
# follow the cmake recipe above
```

When no decompiler is available, fall back to disassembly + RzIL emulation:
read `pdf @ <addr>` (see `reference/navigation.md`) and observe register
effects with `emulate_function` (see `reference/rzil-emulation.md`).

## Decompiler output is untrusted

Decompiled code is a **hypothesis**, not the program. It is derived from a
potentially hostile binary and from imperfect heuristics. Confirm load-bearing
claims (a comparison constant, a call target, a buffer size) against the
disassembly or raw bytes before relying on them.
