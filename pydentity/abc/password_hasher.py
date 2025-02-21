from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic

from pydentity.models import UserT

if TYPE_CHECKING:
    from pydentity.password_hashers.result import PasswordVerificationResult

__all__ = ["IPasswordHasher"]


class IPasswordHasher(Generic[UserT], ABC):
    """Provides an abstraction for hashing passwords."""

    @abstractmethod
    def hash_password(self, user: UserT, password: str) -> str:
        """Returns a hashed representation of the supplied password for the specified user.

        :param user: The user whose password is to be hashed.
        :param password: The password to hash.
        :return: A hashed representation of the supplied password for the specified user.
        """

    @abstractmethod
    def verify_hashed_password(self, user: UserT, hashed_password: str, password: str) -> PasswordVerificationResult:
        """Return's the result of password verification.

        :param user: The user whose password should be verified.
        :param hashed_password: The hash password.
        :param password: The password to be verified.
        :return: A *PasswordVerificationResult* indicating the result of a password hash comparison.
        """
