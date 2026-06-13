# RzIL emulation: `emulate_function` and raw RzIL control

## Table of contents
- [What RzIL emulation is (and is not)](#what-rzil-emulation-is-and-is-not)
- [Using emulate_function(addr)](#using-emulate_functionaddr)
- [Arch-coverage caveat](#arch-coverage-caveat)
- [Driving RzIL manually via raw cmd](#driving-rzil-manually-via-raw-cmd)
- [Seeding registers and memory](#seeding-registers-and-memory)
- [Safety](#safety)

## What RzIL emulation is (and is not)

RzIL is rizin's intermediate language. Emulating it **interprets** the lifted
semantics of instructions inside rizin — it **never runs the target's native
machine code**. This makes it Tier 1: safe to run on untrusted binaries. It is
how you observe what a function *computes* without executing it on your CPU.

## Using `emulate_function(addr)`

```python
result = re.emulate_function(0x1149, steps=20)
# {
#   "supported":  True,
#   "steps_run":  20,                # how many RzIL steps actually ran
#   "registers":  {...},             # register state after stepping (from `arj`)
#   "note":       "RzIL emulation, no native execution",
# }
```

The verb resets the RzIL VM at `addr` (`aezi`), seeks there, and single-steps up
to `steps` RzIL instructions (`aezse`), stopping early on an invalid/error step.
Afterward it captures register state via `arj`. Increase `steps` for longer
traces; keep it small while exploring.

## Arch-coverage caveat

RzIL uplift coverage is **uneven across architectures and instructions.** Not
every instruction on every arch is lifted. When the architecture lacks RzIL
support, `emulate_function` degrades cleanly instead of emitting wrong results:

```python
{"supported": False, "steps_run": 0, "registers": {},
 "note": "RzIL not supported for this architecture: <message>"}
```

If `supported` is `False`, do not guess at behavior — fall back to reading the
disassembly (`pdf`) and decompilation. A partial trace (small `steps_run`
relative to `steps`) can also mean stepping hit an unlifted instruction; inspect
the disasm at the stopping point.

## Driving RzIL manually via raw cmd

For finer control than the verb, use the raw escape hatch. Core RzIL commands on
rizin 0.8.2:

- `re.cmd(f"aezi @ {addr}")` — initialize/reset the RzIL VM (optionally at addr).
- `re.cmd(f"s {addr}")` — seek to where you want to start.
- `re.cmd("aezse")` — step one RzIL instruction (the verb's stepping primitive).
- `re.cmdj("arj")` — read all registers as JSON (capture state).
- `re.cmd("ar <reg>")` — read a single register.

## Seeding registers and memory

Set up inputs before stepping:

```python
re.cmd("aezi")                 # reset VM
re.cmd("ar rdi=0x1000")        # set argument register
re.cmd("ar rsi=5")             # set another argument
# (write memory at an address before stepping if the function reads it)
for _ in range(20):
    re.cmd("aezse")
print(re.cmdj("arj"))          # inspect resulting register state
```

Adapt register names to the arch (`rdi/rsi/...` on x86-64, `x0/x1/...` on
AArch64, etc.). Read the function's disasm first to know which registers carry
its inputs.

## Safety

RzIL emulation does not execute native code and does not perform native syscalls.
Memory writes during emulation affect only the in-rizin VM. Keep emulation writes
scoped to what you are analyzing; do not use it as a substitute for the
sandbox-gated Tier-2 native debug (see `reference/debug-sandbox.md`).
