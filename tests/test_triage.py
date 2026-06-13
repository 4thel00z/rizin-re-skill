from harness import RizinRE


def test_triage_binary_shape(fixture_path):
    with RizinRE(fixture_path) as re:
        t = re.triage_binary()
    assert set(t) >= {"info", "imports", "strings", "sections", "entrypoint", "function_count"}
    assert t["info"]["arch"]
    assert any("strcmp" in name for name in t["imports"])
    assert any("secret_flag_abc" in s for s in t["strings"])
    assert isinstance(t["function_count"], int) and t["function_count"] > 0
