"""rizin-re skill harness: deterministic safety/bulk verbs over a warm session.

Exploratory work uses the raw ``cmd``/``cmdj`` escape hatch (see reference docs).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from rzpipe.session import RizinSession

log = logging.getLogger("rizin-re")


class AnnotationError(Exception):
    """An annotation plan referenced an address/flag that does not exist."""

_STRING_LIMIT = 200
_IMPORT_LIMIT = 200
_MAP_LIMIT = 300


class RizinRE:
    def __init__(self, path: str, *, analysis: str = "aaa", **kw: Any) -> None:
        self.session = RizinSession(path, analysis=analysis, **kw)

    # raw escape hatch -----------------------------------------------------
    def cmd(self, c: str) -> str:
        return self.session.cmd(c)

    def cmdj(self, c: str) -> Any:
        return self.session.cmdj(c)

    # deterministic bulk verb ---------------------------------------------
    def triage_binary(self) -> dict:
        """One token-budgeted sweep of the static facts about the binary."""
        info = self.session.bin_info()
        imports = [i.name for i in self.session.imports()][:_IMPORT_LIMIT]
        strings = [s.string for s in self.session.strings()][:_STRING_LIMIT]
        sections = [
            {"name": s.get("name", ""), "size": s.get("size", 0),
             "perm": s.get("perm", "")}
            for s in (self.session.cmdj("iSj") or [])
        ]
        entry = self.session.cmdj("iej") or []
        entrypoint = entry[0].get("vaddr") if entry else None
        funcs = self.session.functions()
        return {
            "info": {"arch": info.arch, "bits": info.bits,
                     "type": info.bintype, "os": info.os},
            "imports": imports,
            "strings": strings,
            "sections": sections,
            "entrypoint": entrypoint,
            "function_count": len(funcs),
        }

    def map_functions(self) -> list[dict]:
        """Rank functions by a triage score: size + xref + call-density."""
        rows = []
        for f in self.session.functions():
            xrefs = len(self.session.cmdj(f"axtj @ {f.offset}") or [])
            calls = len(self.session.cmdj(f"axfj @ {f.offset}") or [])
            score = f.size + xrefs * 10 + calls * 2
            rows.append({
                "name": f.name, "offset": f.offset, "size": f.size,
                "xrefs": xrefs, "calls": calls, "score": score,
            })
        rows.sort(key=lambda r: r["score"], reverse=True)
        return rows[:_MAP_LIMIT]

    def _addr_exists(self, addr: int) -> bool:
        # fd resolves a flag/function at an address; empty result means nothing there
        info = self.session.cmdj(f"afij @ {addr}") or []
        if info:
            return True
        # fall back: is there a mapped flag or valid instruction here?
        # rizin 0.8.2 emits a bare error token ("invalid"/"unaligned") at
        # unmapped/unaligned addresses instead of a mnemonic.
        disasm = (self.session.cmd(f"pi 1 @ {addr}") or "").strip().lower()
        return bool(disasm) and "invalid" not in disasm and "unaligned" not in disasm

    def annotate(self, plan: list[dict]) -> None:
        """Validate every op's address, then apply all — or refuse the whole plan."""
        for op in plan:
            addr = op["addr"]
            if not self._addr_exists(addr):
                raise AnnotationError(
                    f"address {addr:#x} does not resolve to code/function; "
                    f"refusing entire plan (no partial apply)"
                )
        for op in plan:
            addr, kind = op["addr"], op["kind"]
            if kind == "rename":
                self.session.cmd(f"afn {op['name']} @ {addr}")
            elif kind == "comment":
                self.session.cmd(f"CC {op['text']} @ {addr}")
            elif kind == "var_rename":
                self.session.cmd(f"afvn {op['new']} {op['old']} @ {addr}")
            else:
                raise AnnotationError(f"unknown annotation kind: {kind!r}")

    def quit(self) -> None:
        self.session.quit()

    def __enter__(self) -> "RizinRE":
        return self

    def __exit__(self, *exc) -> None:
        self.quit()
