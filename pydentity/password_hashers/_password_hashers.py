from __future__ import annotations

from typing import TYPE_CHECKING, Generic, Literal

from pwdlib import PasswordHash

from pydentity.abc.password_hasher import IPasswordHasher
from pydentity.exc import ArgumentNoneError
from pydentity.models import UserT
from pydentity.password_hashers.result import PasswordVerificationResult

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cryptography.hazmat.primitives.hashes import HashAlgorithm
    from pwdlib.hashers import HasherProtocol

__all__ = (
    "Argon2PasswordHasher",
    "BcryptPasswordHasher",
    "PBKDF2PasswordHasher",
    "PasswordHasher",
)


class PasswordHasher(IPasswordHasher[UserT], Generic[UserT]):
    """Implements the standard password hashing."""

    __slots__ = ("_hasher",)

    def __init__(self, hashers: Sequence[HasherProtocol]) -> None:
        self._hasher = PasswordHash(hashers)

    def hash_password(self, user: UserT, password: str) -> str:
        if password is None:
            raise ArgumentNoneError("password")
        return self._hasher.hash(password)

    def verify_hashed_password(self, user: UserT, hashed_password: str, password: str) -> PasswordVerificationResult:
        if password is None or hashed_password is None:
            return PasswordVerificationResult.Failed
        valid, hash_updated = self._hasher.verify_and_update(password, hashed_password)
        if valid:
            if hash_updated is not None:
                return PasswordVerificationResult.SuccessRehashNeeded
            return PasswordVerificationResult.Success
        return PasswordVerificationResult.Failed


class BcryptPasswordHasher(PasswordHasher[UserT], Generic[UserT]):
    def __init__(self, rounds: int = 12, prefix: Literal["2a", "2b"] = "2b") -> None:
        """Create a Bcrypt password hasher.

        :param rounds: The number of rounds to use for hashing.
        :param prefix: The prefix to use for hashing.
        """
        from .hashers import BcryptHasher

        super().__init__((BcryptHasher(rounds=rounds, prefix=prefix),))


class Argon2PasswordHasher(PasswordHasher[UserT], Generic[UserT]):
    def __init__(
        self,
        time_cost: int = 3,
        memory_cost: int = 65536,
        parallelism: int = 4,
        hash_len: int = 32,
        salt_len: int = 16,
    ) -> None:
        """Create a Argon2 password hasher.

        :param time_cost: Defines the amount of computation realized and therefore the execution time,
            given in number of iterations.
        :param memory_cost: Defines the memory usage, given in KiB.
        :param parallelism: Defines the number of parallel threads (*changes* the resulting hash value).
        :param hash_len: Length of the hash in bytes.
        :param salt_len: Length of random salt to be generated for each password.
        """
        from .hashers import Argon2Hasher

        super().__init__(
            (
                Argon2Hasher(
                    time_cost=time_cost,
                    memory_cost=memory_cost,
                    parallelism=parallelism,
                    hash_len=hash_len,
                    salt_len=salt_len,
                ),
            )
        )


class PBKDF2PasswordHasher(PasswordHasher[UserT], Generic[UserT]):
    def __init__(
        self,
        algorithm: HashAlgorithm | None = None,
        hash_len: int = 32,
        iterations: int = 720000,
    ) -> None:
        """Create a PBKDF2 password hasher.

        :param algorithm: An instance of *HashAlgorithm*.
        :param hash_len: The desired length of the derived key in bytes.
        :param iterations: The number of iterations to perform of the hash function.
            This can be used to control the length of time the operation takes.
            Higher numbers help mitigate brute force attacks against derived keys.
        """
        from .hashers import PBKDF2Hasher

        super().__init__((PBKDF2Hasher(algorithm=algorithm, hash_len=hash_len, iterations=iterations),))
