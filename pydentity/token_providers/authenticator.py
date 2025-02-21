from __future__ import annotations

from typing import TYPE_CHECKING, Any, Generic

from pydentity.abc.token_provider import IUserTwoFactorTokenProvider
from pydentity.models import UserT
from pydentity.rfc6238_authentication_service import validate_code
from pydentity.utils import is_none_or_whitespace

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager

__all__ = ["AuthenticatorTokenProvider"]


class AuthenticatorTokenProvider(IUserTwoFactorTokenProvider[UserT], Generic[UserT]):
    """Used for authenticator code verification."""

    __slots__ = ("digest", "digits", "interval")

    def __init__(self, digits: int = 6, digest: Any = None, interval: int = 30) -> None:
        """Constructs a new instance of an *AuthenticatorTokenProvider[TUser]*.

        :param digits: Number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        :param digest: Digest function to use in the HMAC (expected to be SHA1)
        :param interval: The time interval in seconds for OTP. This defaults to 30.
        """
        self.digits = digits
        self.digest = digest
        self.interval = interval

    async def generate(self, manager: UserManager[UserT], purpose: str, user: UserT) -> str:
        """Returns an empty string since no authenticator codes are sent.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param purpose: The purpose the token will be used for.
        :param user: The user a token should be generated for.
        :return: An empty string.
        """
        return ""

    async def validate(self, manager: UserManager[UserT], purpose: str, token: str, user: UserT) -> bool:
        key = await manager.get_authenticator_key(user)
        if key is None or is_none_or_whitespace(key):
            return False
        return validate_code(key, token, self.digits, self.digest, self.interval)

    async def can_generate_two_factor(self, manager: UserManager[UserT], user: UserT) -> bool:
        key = await manager.get_authenticator_key(user)
        return not is_none_or_whitespace(key)
