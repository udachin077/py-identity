import string
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Final

from pydentity.abc.token_provider import IUserTwoFactorTokenProvider
from pydentity.models import UserT
from pydentity.security.claims import ClaimTypes

__all__ = [
    "ClaimsIdentityOptions",
    "IdentityOptions",
    "LockoutOptions",
    "PasswordOptions",
    "SignInOptions",
    "TokenOptions",
    "UserOptions",
]

ALLOWED_USERNAME_CHARS: Final[str] = "".join([string.ascii_letters, string.digits, "._-@"])


@dataclass
class LockoutOptions:
    """Options for configuring user lockout."""

    allowed_for_new_user: bool = field(default=True)
    """Gets or sets a flag indicating whether a new user can be locked out. Defaults to *True*."""
    default_lockout_timespan: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    """Gets or sets the *timedelta* a user is locked out for when a lockout occurs. Defaults to *5* minutes."""
    max_failed_access_attempts: int = field(default=5)
    """Gets or sets the number of failed access attempts allowed before a user is locked out,
    assuming lock out is enabled. Defaults to *5*."""


@dataclass
class ClaimsIdentityOptions:
    """Options used to configure the claim types used for well known claims."""

    role_claim_type: str = field(default=ClaimTypes.Role)
    """Gets or sets the *ClaimTypes* used for a role claim. Defaults to *ClaimTypes.Role*."""
    username_claim_type: str = field(default=ClaimTypes.Name)
    """Gets or sets the *ClaimTypes* used for the user name claim. Defaults to *ClaimTypes.Name*."""
    user_id_claim_type: str = field(default=ClaimTypes.NameIdentifier)
    """Gets or sets the *ClaimTypes* used for the user identifier claim. Defaults to *ClaimTypes.NameIdentifier*."""
    email_claim_type: str = field(default=ClaimTypes.Email)
    """Gets or sets the `ClaimTypes` used for the user email claim. Defaults to `ClaimTypes.Email`."""
    security_stamp_claim_type: str = field(default=ClaimTypes.SecurityStamp)
    """Gets or sets the *ClaimTypes* used for the security stamp claim. Defaults to *ClaimTypes.SecurityStamp*."""


@dataclass
class PasswordOptions:
    """Specifies options for password requirements."""

    required_digit: bool = field(default=True)
    """Gets or sets a flag indicating if passwords must contain a digit. Defaults to *True*."""
    required_length: int = field(default=8)
    """Gets or sets the minimum length a password must be. Defaults to *8*."""
    required_unique_chars: int = field(default=1)
    """Gets or sets the minimum number of unique characters which a password must contain. Defaults to *1*."""
    required_lowercase: bool = field(default=True)
    """Gets or sets a flag indicating if passwords must contain a lower case ASCII character. Defaults to *True*."""
    required_non_alphanumeric: bool = field(default=True)
    """Gets or sets a flag indicating if passwords must contain a non-alphanumeric character. Defaults to *True*."""
    required_uppercase: bool = field(default=True)
    """Gets or sets a flag indicating if passwords must contain a upper case ASCII character. Defaults to *True*."""


@dataclass
class SignInOptions:
    """Options for configuring sign-in."""

    required_confirmed_email: bool = field(default=False)
    """Gets or sets a flag indicating whether a confirmed email address is required to sign in.
    Defaults to *False*."""
    required_confirmed_phone_number: bool = field(default=False)
    """Gets or sets a flag indicating whether a confirmed telephone number is required to sign in.
    Defaults to *False*."""
    required_confirmed_account: bool = field(default=True)
    """Gets or sets a flag indicating whether a confirmed *IUserConfirmation[TUser]* account is required to sign in.
    Defaults to *True*."""


@dataclass
class TokenOptions:
    """Options for user tokens."""

    DEFAULT_PROVIDER: Final[str] = field(default="Default", init=False)
    DEFAULT_EMAIL_PROVIDER: Final[str] = field(default="Email", init=False)
    DEFAULT_PHONE_PROVIDER: Final[str] = field(default="Phone", init=False)
    DEFAULT_AUTHENTICATION_PROVIDER: Final[str] = field(default="Authenticator", init=False)

    authenticator_token_provider: str = field(default=DEFAULT_AUTHENTICATION_PROVIDER)
    """Gets or sets the token provider used to validate two factor sign ins with an authenticator."""
    change_email_token_provider: str = field(default=DEFAULT_EMAIL_PROVIDER)
    """Gets or sets the token provider used to generate tokens used in email change confirmation emails."""
    change_phone_number_token_provider: str = field(default=DEFAULT_PHONE_PROVIDER)
    """Gets or sets the token provider used to generate tokens used when changing phone numbers."""
    email_confirmation_token_provider: str = field(default=DEFAULT_EMAIL_PROVIDER)
    """Gets or sets the token provider used to generate tokens used in account confirmation emails."""
    phone_number_confirmation_token_provider: str = field(default=DEFAULT_PHONE_PROVIDER)
    """Gets or sets the token provider used to generate tokens used in account confirmation phone number."""
    password_reset_token_provider: str = field(default=DEFAULT_PROVIDER)
    """Gets or sets the token provider used to generate tokens used in password reset emails."""
    provider_map: dict[str, IUserTwoFactorTokenProvider[UserT]] = field(default_factory=dict)  # type: ignore[valid-type]
    """Will be used to construct user token providers with the key used as the provider name."""


@dataclass
class UserOptions:
    """Options for user validation."""

    allowed_username_characters: str = field(default=ALLOWED_USERNAME_CHARS)
    """Gets or sets the list of allowed characters in the username used to validate user names.
    Defaults to *abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@*"""
    require_unique_email: bool = field(default=True)
    """Gets or sets a flag indicating whether the application requires unique emails for its auth.
    Defaults to *True*."""
    allowed_email_domains: Sequence[str] | None = field(default=None)
    """Gets or sets a list of available domains for email. If the *None* then any domains are available.
    Defaults to *None*."""


@dataclass
class IdentityOptions:
    """Represents all the options you can use to configure the builders system."""

    claims_identity: ClaimsIdentityOptions = field(default_factory=ClaimsIdentityOptions)
    """Gets or sets the *ClaimsIdentityOptions* for the builders system."""
    lockout: LockoutOptions = field(default_factory=LockoutOptions)
    """Gets or sets the *LockoutOptions* for the builders system."""
    password: PasswordOptions = field(default_factory=PasswordOptions)
    """Gets or sets the *PasswordOptions* for the builders system."""
    signin: SignInOptions = field(default_factory=SignInOptions)
    """Gets or sets the *SignInOptions* for the builders system."""
    tokens: TokenOptions = field(default_factory=TokenOptions)
    """Gets or sets the *TokenOptions* for the builders system."""
    user: UserOptions = field(default_factory=UserOptions)
    """Gets or sets the *UserOptions* for the builders system."""
