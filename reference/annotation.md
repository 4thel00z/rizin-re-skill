# Annotation: plan-validate-execute

## Table of contents
- [The plan schema](#the-plan-schema)
- [Whole-plan refusal semantics](#whole-plan-refusal-semantics)
- [How addresses are validated](#how-addresses-are-validated)
- [Worked example](#worked-example)
- [Persisting a project for resumable analysis](#persisting-a-project-for-resumable-analysis)

## The plan schema

`annotate(plan)` takes a list of operation dicts. Three kinds are supported:

```python
plan = [
    {"kind": "rename",     "addr": 0x1149, "name": "validate_password"},
    {"kind": "comment",    "addr": 0x1149, "text": "compares arg against 'rizin'"},
    {"kind": "var_rename", "addr": 0x1149, "new": "secret", "old": "var_8h"},
]
re.annotate(plan)
```

| kind         | required keys                | rizin command applied        |
|--------------|------------------------------|------------------------------|
| `rename`     | `addr`, `name`               | `afn <name> @ <addr>`        |
| `comment`    | `addr`, `text`               | `CC <text> @ <addr>`         |
| `var_rename` | `addr`, `new`, `old`         | `afvn <new> <old> @ <addr>`  |

`rename` renames the **function** at `addr`. `var_rename` renames a local
variable (`old` -> `new`) within the function at `addr`. Any unknown `kind`
raises `AnnotationError`.

## Whole-plan refusal semantics

The verb runs in two phases:

1. **Validate** — every op's `addr` is checked first. If any address does not
   resolve to code/a function, the verb raises `AnnotationError` and applies
   **nothing**.
2. **Execute** — only if all addresses validated, every op is applied.

This is deliberate: it blocks hallucinated-address corruption. There is **no
partial apply** — a plan with one bad address leaves the project untouched, so a
single typo or model error cannot silently rename the wrong function. Build the
whole plan, then submit it once.

## How addresses are validated

`_addr_exists(addr)` first asks `afij @ <addr>` (function info as JSON); a
non-empty result means a function is there. If empty, it falls back to
disassembling one instruction (`pi 1 @ <addr>`) and accepts the address only if
it yields a real mnemonic. On rizin 0.8.2 an unmapped or misaligned address
prints the bare token `invalid` or `unaligned` instead of a mnemonic — the
validator treats those as "does not exist" and refuses the plan.

So valid targets are: an address inside a known function, or any address that
disassembles to a real instruction. A random/unmapped address (e.g. `0xDEADBEEF`)
is refused.

## Worked example

```python
from harness import RizinRE, AnnotationError

with RizinRE("/path/to/bin") as re:
    off = next(f.offset for f in re.session.functions() if "check" in f.name)
    try:
        re.annotate([
            {"kind": "rename",  "addr": off,        "name": "validate_input"},
            {"kind": "comment", "addr": off,        "text": "true iff arg == 'rizin'"},
            {"kind": "rename",  "addr": 0xDEADBEEF, "name": "oops"},  # bad
        ])
    except AnnotationError as e:
        print("refused, nothing applied:", e)
    # because the third op is invalid, the rename to validate_input did NOT apply
```

Drop the bad op and re-submit to apply the rest.

## Persisting a project for resumable analysis

Annotations live in the rizin session. To keep them across sessions, save a
project file via the raw escape hatch:

```python
re.cmd("Ps /path/to/analysis.rzdb")    # save project
```

In a later session, load it back:

```python
re.cmd("Po /path/to/analysis.rzdb")    # open project
```

Saving after a batch of annotations makes long analyses resumable and lets you
hand the project to a teammate.
