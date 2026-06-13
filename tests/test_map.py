from harness import RizinRE


def test_map_functions_ranked_and_scored(fixture_path):
    with RizinRE(fixture_path) as re:
        funcs = re.map_functions()
    assert funcs, "expected at least one function"
    # each row has the expected fields
    for f in funcs:
        assert set(f) >= {"name", "offset", "size", "xrefs", "calls", "score"}
    # deterministic: sorted by score descending
    scores = [f["score"] for f in funcs]
    assert scores == sorted(scores, reverse=True)
