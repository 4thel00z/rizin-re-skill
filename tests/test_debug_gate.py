import pytest
from harness import RizinRE, SandboxError


def test_debug_refused_without_sandbox_env(fixture_path, monkeypatch):
    monkeypatch.delenv("RIZIN_RE_SANDBOX_CONFIRMED", raising=False)
    with RizinRE(fixture_path) as re:
        with pytest.raises(SandboxError):
            re.debug_session(human_ack=True)


def test_debug_refused_without_human_ack(fixture_path, monkeypatch):
    monkeypatch.setenv("RIZIN_RE_SANDBOX_CONFIRMED", "1")
    with RizinRE(fixture_path) as re:
        with pytest.raises(SandboxError):
            re.debug_session(human_ack=False)
