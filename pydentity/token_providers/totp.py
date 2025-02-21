from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any, Generic, override
from uuid import UUID

import pydentity.rfc6238_authentication_service as rfc6238
from pydentity.abc.token_provider import IUserTwoFactorTokenProvider
from pydentity.models import UserT
from pydentity.utils import ensure_bytes, ensure_str, is_none_or_whitespace

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager

__all__ = ["EmailTokenProvider", "PhoneNumberTokenProvider", "TotpSecurityStampBasedTokenProvider"]


def _apply_key_modifier(key: bytes | str | UUID, key_modifier: bytes | str | None = None) -> str:
    if isinstance(key, UUID):
        key = key.bytes
    key = ensure_bytes(key)
    key_modifier = ensure_bytes(key_modifier) if key_modifier else None
    return ensure_str(base64.b32encode(key + key_modifier if key_modifier else key))


class TotpSecurityStampBasedTokenProvider(IUserTwoFactorTokenProvider[UserT], Generic[UserT]):
    def __init__(self, digits: int = 6, digest: Any = None, interval: int = 180) -> None:
        """Constructs a new instance of the *TotpSecurityStampBasedTokenProvider[TUser]*.

        :param digits: Number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        :param digest: Digest function to use in the HMAC (expected to be SHA1)
        :param interval: The time interval in seconds for OTP. This defaults to 180.
        """
        self.digits = digits
        self.digest = digest
        self.interval = interval

    async def can_generate_two_factor(self, manager: UserManager[UserT], user: UserT) -> bool:
        raise NotImplementedError()

    async def generate(self, manager: UserManager[UserT], purpose: str, user: UserT) -> str:
        """Generates a token for the specified user and purpose.

        The purpose parameter allows a token generator to be used for multiple types of token whilst
        insuring a token for one purpose cannot be used for another. For example if you specified a purpose of "Email"
        and validated it with the same purpose a token with the purpose of TOTP would not pass the check even if it was
        for the same user.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param purpose: The purpose the token will be used for.
        :param user: The user a token should be generated for.
        :return:
        """
        security_token = await manager.create_security_token(user)
        modifier = await self.get_user_modifier(manager, purpose, user)
        secret = _apply_key_modifier(security_token, modifier)
        return rfc6238.generate_code(secret, self.digits, self.digest, self.interval)

    async def validate(self, manager: UserManager[UserT], purpose: str, token: str, user: UserT) -> bool:
        """Returns a flag indicating whether the specified token is valid for the given user and purpose.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param purpose: The purpose the token will be used for.
        :param token: The token to validate.
        :param user: The user a token should be validated for.
        :return:
        """
        security_token = await manager.create_security_token(user)
        modifier = await self.get_user_modifier(manager, purpose, user)
        secret = _apply_key_modifier(security_token, modifier)
        return rfc6238.validate_code(secret, token, self.digits, self.digest, self.interval)

    async def get_user_modifier(self, manager: UserManager[UserT], purpose: str, user: UserT) -> bytes:
        """Returns a constant, provider and user unique modifier used for entropy in generated tokens
        from user information.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param purpose: The purpose the token will be generated for.
        :param user: The user a token should be generated for.
        :return:
        """
        user_id = await manager.get_user_id(user)
        return ensure_bytes(f"Totp:{purpose}:{user_id}")


class EmailTokenProvider(TotpSecurityStampBasedTokenProvider[UserT], Generic[UserT]):
    """TokenProvider that generates tokens from the users security stamp and notifies a user via email."""

    @override
    async def can_generate_two_factor(self, manager: UserManager[UserT], user: UserT) -> bool:
        email = await manager.get_email(user)
        return not is_none_or_whitespace(email) and await manager.is_email_confirmed(user)

    @override
    async def get_user_modifier(self, manager: UserManager[UserT], purpose: str, user: UserT) -> bytes:
        email = await manager.get_email(user)
        return ensure_bytes(f"Email:{purpose}:{email}")


class PhoneNumberTokenProvider(TotpSecurityStampBasedTokenProvider[UserT], Generic[UserT]):
    """Represents a token provider that generates tokens from a user security stamp and
    sends them to the user via their phone number.
    """

    @override
    async def can_generate_two_factor(self, manager: UserManager[UserT], user: UserT) -> bool:
        phone_number = await manager.get_phone_number(user)
        return not is_none_or_whitespace(phone_number) and await manager.is_phone_number_confirmed(user)

    @override
    async def get_user_modifier(self, manager: UserManager[UserT], purpose: str, user: UserT) -> bytes:
        phone_number = await manager.get_phone_number(user)
        return ensure_bytes(f"PhoneNumber:{purpose}:{phone_number}")
