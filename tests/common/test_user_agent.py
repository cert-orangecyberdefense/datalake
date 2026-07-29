import pytest

from datalake.common import user_agent as user_agent_mod
from datalake.common.user_agent import (
    USER_AGENT_INTEGRATION_ENV,
    build_user_agent,
)


@pytest.fixture
def fixed_version(monkeypatch):
    monkeypatch.setattr(user_agent_mod, "_get_version", lambda: "9.9.9")
    return "9.9.9"


def test_build_user_agent_default(monkeypatch, fixed_version):
    monkeypatch.delenv(USER_AGENT_INTEGRATION_ENV, raising=False)
    assert build_user_agent() == f"datalake-python-sdk/{fixed_version}"


def test_build_user_agent_with_integration(monkeypatch, fixed_version):
    monkeypatch.setenv(USER_AGENT_INTEGRATION_ENV, "my-soar/2.1")
    assert build_user_agent() == f"my-soar/2.1 datalake-python-sdk/{fixed_version}"


@pytest.mark.parametrize("value", ["", "   "])
def test_build_user_agent_ignores_empty_or_whitespace(
    monkeypatch, fixed_version, value
):
    monkeypatch.setenv(USER_AGENT_INTEGRATION_ENV, value)
    assert build_user_agent() == f"datalake-python-sdk/{fixed_version}"


def test_build_user_agent_strips_surrounding_whitespace(monkeypatch, fixed_version):
    monkeypatch.setenv(USER_AGENT_INTEGRATION_ENV, "  foo/1.0  ")
    assert build_user_agent() == f"foo/1.0 datalake-python-sdk/{fixed_version}"
