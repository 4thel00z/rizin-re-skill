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
    assert set(result) >= {"available", "code", "decompiler", "mismatches"}
    if result["available"]:
        assert isinstance(result["code"], str) and result["code"]
        assert isinstance(result["mismatches"], list)
    else:
        # graceful degradation: no plugin, but a clear message and no crash
        assert "decompiler" in result["code"].lower() or result["code"] == ""
