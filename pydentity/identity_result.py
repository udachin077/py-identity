from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Self

from pydentity.identity_error import IdentityError

__all__ = ["IdentityResult"]


@dataclass
class IdentityResult:
    """Represents the result of an builders operation."""

    succeeded: bool = field(default=False)
    """Flag indicating whether if the operation succeeded or not."""
    errors: Iterable[IdentityError] = field(default_factory=tuple)
    """An *Iterable* of *IdentityError* instances containing errors that occurred during the builders operation."""

    @classmethod
    def failed(cls, *errors: IdentityError) -> Self:
        """Creates an *IdentityResult* indicating a failed builders operation, with a list of errors if applicable."""
        return cls(False, errors)

    @classmethod
    def success(cls) -> Self:
        """Returns an *IdentityResult* indicating a successful builders operation."""
        return cls(True)

    def __str__(self) -> str:
        if self.succeeded:
            return "Succeeded."
        return f"Failed: {','.join(e.code for e in self.errors)}."
