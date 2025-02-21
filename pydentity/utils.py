from datetime import datetime, timezone
from functools import cache

__all__ = [
    "ensure_bytes",
    "ensure_str",
    "get_machineid_key",
    "is_none_or_whitespace",
    "normalize_datetime",
]


def is_none_or_whitespace(v: str | None, /) -> bool:
    return bool(not v or v.isspace())


def ensure_str(v: str | bytes, *, encoding: str = "utf-8") -> str:
    return v.decode(encoding) if isinstance(v, bytes) else v


def ensure_bytes(v: str | bytes, *, encoding: str = "utf-8") -> bytes:
    return v.encode(encoding) if isinstance(v, str) else v


def normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is not None:
        value.astimezone(timezone.utc)
    return value.replace(microsecond=0)


@cache
def get_machineid_key(key: str = "pyidentity") -> bytes:
    try:
        import machineid
    except ImportError as error:
        raise RuntimeError(
            'The installed "py-machineid" package is required to generate key.\n'
            'You can install "py-machineid" with:\n'
            "pip install py-machineid"
        ) from error

    return ensure_bytes(machineid.hashed_id(key))
