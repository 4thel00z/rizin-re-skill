import pytest

from harness import RizinRE


def _check_offset(re):
    for f in re.session.functions():
        if "check" in f.name:
            return f.offset
    raise AssertionError("check function not found")


def test_decompile_reports_available_flag(fixture_path):
    with RizinRE(fixture_path) as re:
        off = _check_offset(re)
        result = re.decompile(off)
    assert set(result) >= {"available", "code", "decompiler", "annotations", "mismatches"}
    if result["available"]:
        assert result["decompiler"] in ("rz-ghidra", "jsdec")
        assert isinstance(result["code"], str) and result["code"]
        assert isinstance(result["mismatches"], list)
        assert isinstance(result["annotations"], list)
    else:
        assert "decompiler" in result["code"].lower() or result["code"] == ""


def test_decompile_uses_ghidra_json_when_available(fixture_path):
    """If rz-ghidra (pdg) is installed, decompile() must use its JSON path."""
    with RizinRE(fixture_path) as re:
        if not re._has_command("pdg"):
            pytest.skip("rz-ghidra (pdg) not installed")
        off = _check_offset(re)
        result = re.decompile(off)
    assert result["available"] is True
    assert result["decompiler"] == "rz-ghidra"
    assert "check" in result["code"] or "strcmp" in result["code"]
    assert isinstance(result["annotations"], list)
