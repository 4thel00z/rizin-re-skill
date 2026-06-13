from harness import RizinRE


def _check_offset(re):
    for f in re.session.functions():
        if "check" in f.name:
            return f.offset
    raise AssertionError("check function not found")


def test_emulate_returns_supported_flag_and_effects(fixture_path):
    with RizinRE(fixture_path) as re:
        off = _check_offset(re)
        result = re.emulate_function(off, steps=20)
    assert set(result) >= {"supported", "steps_run", "registers", "note"}
    if not result["supported"]:
        assert result["note"]  # clear message about why
    else:
        assert isinstance(result["registers"], dict)
