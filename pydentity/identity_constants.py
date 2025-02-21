from typing import Final

__all__ = ["IdentityConstants"]


class IdentityConstants:
    """Represents all the options you can use to configure the cookies middleware used by the identity system."""

    __IdentityPrefix: Final[str] = "PyIdentity"
    ApplicationScheme: Final[str] = __IdentityPrefix + ".Application"
    """The scheme used to identify application authentication cookies."""
    BearerScheme: Final[str] = __IdentityPrefix + ".Bearer"
    """The scheme used to identify bearer authentication tokens."""
    BearerAndApplicationScheme: Final[str] = __IdentityPrefix + ".BearerAndApplication"
    """The scheme used to identify combination of *BearerScheme* and *ApplicationScheme*."""
    ExternalScheme: Final[str] = __IdentityPrefix + ".External"
    """The scheme used to identify external authentication cookies."""
    TwoFactorRememberMeScheme: Final[str] = __IdentityPrefix + ".TwoFactorRememberMe"
    """The scheme used to identify Two Factor authentication cookies for saving the Remember Me state."""
    TwoFactorUserIdScheme: Final[str] = __IdentityPrefix + ".TwoFactorUserId"
    """The scheme used to identify Two Factor authentication cookies for round tripping user identities."""
