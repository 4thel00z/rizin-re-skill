import pytest
from harness import RizinRE, AnnotationError


def _check_offset(re):
    for f in re.session.functions():
        if "check" in f.name:
            return f.offset
    raise AssertionError("check function not found")


def test_annotate_applies_valid_plan(fixture_path):
    with RizinRE(fixture_path) as re:
        off = _check_offset(re)
        re.annotate([
            {"kind": "rename", "addr": off, "name": "validate_password"},
            {"kind": "comment", "addr": off, "text": "compares against 'rizin'"},
        ])
        names = {f.name for f in re.session.functions()}
        assert any("validate_password" in n for n in names)


def test_annotate_rejects_bogus_address_without_partial_apply(fixture_path):
    with RizinRE(fixture_path) as re:
        off = _check_offset(re)
        with pytest.raises(AnnotationError):
            re.annotate([
                {"kind": "rename", "addr": off, "name": "good_name"},
                {"kind": "rename", "addr": 0xDEADBEEF, "name": "bad_name"},
            ])
        # the valid op must NOT have been applied (whole-plan refusal)
        names = {f.name for f in re.session.functions()}
        assert not any("good_name" in n for n in names)
