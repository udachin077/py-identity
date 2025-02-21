from enum import Enum

__all__ = ["PasswordVerificationResult"]


class PasswordVerificationResult(Enum):
    """Specifies the results for password verification."""

    Failed = 0
    """Indicates password verification failed."""
    Success = 1
    """Indicates password verification was successful."""
    SuccessRehashNeeded = 2
    """Indicates password verification was successful however the password was encoded using a deprecated algorithm
    and should be rehashed and updated."""
