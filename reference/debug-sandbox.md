# Tier-2 native debug and sandbox requirements

## Table of contents
- [When Tier 2 applies](#when-tier-2-applies)
- [The two gates](#the-two-gates)
- [Sandbox requirements (Linux)](#sandbox-requirements-linux)
- [macOS: refused outright](#macos-refused-outright)
- [Driving the debugger once authorized](#driving-the-debugger-once-authorized)

## When Tier 2 applies

Tiers 0 (static) and 1 (RzIL emulation) never run the target's native code and
are safe on untrusted binaries. **Tier 2 — native debugging — actually executes
the binary on the host CPU** (`ood`, `dc`, `ds`, breakpoints). That is dangerous
for untrusted code: it can run arbitrary syscalls, touch the network, persist,
or escape. The harness refuses it unless you have proven you are inside an
isolated sandbox.

## The two gates

`debug_session(*, human_ack)` requires **both**:

1. **Environment confirmation** — `RIZIN_RE_SANDBOX_CONFIRMED=1` must be set in
   the process environment. Set this **only** inside a disposable sandbox.
2. **Per-call human acknowledgement** — `human_ack=True`. A human must
   explicitly authorize this specific debug session.

Missing either raises `SandboxError` and nothing native runs.

```python
# inside a sandbox VM, with RIZIN_RE_SANDBOX_CONFIRMED=1 exported:
with RizinRE("/path/to/sample") as re:
    re.debug_session(human_ack=True)     # returns self; now drive dc/ds/dr via cmd()
```

## Sandbox requirements (Linux)

Before setting `RIZIN_RE_SANDBOX_CONFIRMED=1`, the binary must run inside an
isolated environment with, at minimum:

- **Strong isolation** — a Linux microVM (Firecracker or Kata Containers) or a
  gVisor-sandboxed container. A plain container is weaker; prefer a microVM for
  genuinely untrusted samples.
- **Default-deny egress** — no outbound network unless explicitly required and
  scoped. Assume the sample wants to call home.
- **Resource caps** — CPU, memory, and wall-clock-time limits so a sample cannot
  hang or exhaust the host.
- **Disposable filesystem** — a throwaway rootfs/snapshot you discard after the
  session. Never debug untrusted code against your real home directory.

The environment variable is your attestation that all of the above is true. The
harness cannot verify the sandbox for you; it only enforces that you asserted it.

## macOS: refused outright

On a Darwin host, `debug_session` **always raises `SandboxError`**, regardless of
the env var or `human_ack`. Firecracker and gVisor are Linux-only, so there is no
turnkey isolation primitive on macOS.

To do Tier-2 work from a Mac, run the **entire skill inside a disposable Linux
VM** and treat that VM as the sandbox:

- **Lima** — `limactl start`, then run the skill in the guest.
- **UTM** — a throwaway Linux guest.
- **Docker Desktop** — a Linux container (weaker isolation; acceptable only for
  semi-trusted samples, ideally layered with gVisor via `--runtime=runsc`).

Inside that Linux guest, apply the sandbox requirements above, export
`RIZIN_RE_SANDBOX_CONFIRMED=1`, and call `debug_session(human_ack=True)`.

## Driving the debugger once authorized

`debug_session` returns the `RizinRE` instance; drive native debugging through
the raw escape hatch:

- `re.cmd("ood")` — reopen the file in debug mode (start the debuggee).
- `re.cmd("db <addr>")` — set a breakpoint.
- `re.cmd("dc")` — continue.
- `re.cmd("ds")` — single-step.
- `re.cmdj("drj")` — read registers as JSON.

Every one of these executes native code. Keep the session short, observe, and
discard the sandbox afterward.
