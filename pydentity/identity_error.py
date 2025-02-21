from dataclasses import dataclass

__all__ = ["IdentityError"]


@dataclass
class IdentityError:
    """Encapsulates an error from the identity subsystem."""

    code: str
    """Gets the code for this error."""
    description: str
    """Gets the description for this error."""

    def __str__(self) -> str:
        return f"{self.code}: {self.description}"
