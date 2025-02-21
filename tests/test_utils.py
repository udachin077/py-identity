import pytest

from pydentity.utils import ensure_bytes, ensure_str, is_none_or_whitespace


def test_is_none_or_whitespace() -> None:
    assert is_none_or_whitespace("") is True
    assert is_none_or_whitespace(" ") is True
    assert is_none_or_whitespace("  ") is True
    assert is_none_or_whitespace(None) is True
    assert is_none_or_whitespace("None") is False
    assert is_none_or_whitespace("_") is False
    assert is_none_or_whitespace("  .") is False


@pytest.mark.parametrize("v", ["string", b"string"])
def test_ensure_str(v):
    assert isinstance(ensure_str(v), str)


@pytest.mark.parametrize("v", ["string", b"string"])
def test_ensure_bytes(v):
    assert isinstance(ensure_bytes(v), bytes)
