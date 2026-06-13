import os
import pytest

FIXTURE = os.path.join(os.path.dirname(__file__), "fixture")


@pytest.fixture
def fixture_path():
    assert os.path.exists(FIXTURE), "build tests/fixture first (see plan Task 0)"
    return FIXTURE
