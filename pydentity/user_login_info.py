from dataclasses import dataclass, field

__all__ = ["UserLoginInfo"]


@dataclass
class UserLoginInfo:
    """Represents login information and source for a user record."""

    login_provider: str
    """Gets the provider for this instance of *UserLoginInfo*."""
    provider_key: str
    """Gets the unique identifier for the user identity user provided by the login provider."""
    provider_display_name: str | None = field(default=None)
    """Gets the display name for the provider."""
