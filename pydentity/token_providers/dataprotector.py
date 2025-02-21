from __future__ import annotations

import base64
import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Generic

import msgspec

from pydentity.abc.token_provider import IUserTwoFactorTokenProvider
from pydentity.exc import ArgumentNoneError
from pydentity.models import UserT
from pydentity.utils import ensure_bytes, ensure_str, normalize_datetime

if TYPE_CHECKING:
    from pydentity.abc.data_protector import IDataProtector
    from pydentity.user_manager import UserManager

__all__ = ["DataProtectorTokenProvider"]


class DataProtectorTokenProvider(IUserTwoFactorTokenProvider[UserT], Generic[UserT]):
    """Provides protection and validation of identity tokens."""

    __slots__ = ("_protector", "logger", "token_lifespan")

    def __init__(
        self,
        protector: IDataProtector,
        token_lifespan: timedelta = timedelta(minutes=30),
    ) -> None:
        """Constructs a new instance of a *DataProtectorTokenProvider[TUser]*.

        :param protector: Encryption backend (AES, Fernet, etc.)
        :param token_lifespan: The amount of time a generated token remains valid. Defaults to 30 minutes.
        """
        self._protector = protector
        self.token_lifespan = token_lifespan
        self.logger = logging.getLogger("PyIdentity.DataProtectorTokenProvider")
        """The logger used to log messages, warnings and errors."""

    async def generate(self, manager: UserManager[UserT], purpose: str, user: UserT) -> str:
        if user is None:
            raise ArgumentNoneError("user")

        user_id = await manager.get_user_id(user)
        stamp = await manager.get_security_stamp(user) if manager.supports_user_security_stamp else None
        data = msgspec.json.encode(
            {
                "creation_time": normalize_datetime(datetime.now(timezone.utc)).timestamp(),
                "user_id": user_id,
                "purpose": purpose or "",
                "stamp": stamp or "",
            }
        )
        protected_data = self._protector.encrypt(data)
        return ensure_str(base64.urlsafe_b64encode(protected_data))

    async def can_generate_two_factor(self, manager: UserManager[UserT], user: UserT) -> bool:
        """Checks if a two-factor authentication token can be generated for the specified user.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param user: The user a token could be generated for.
        :returns: This method will always return false for instances of *DataProtectorTokenProvider*.
        """
        return False

    async def validate(self, manager: UserManager[UserT], purpose: str, token: str, user: UserT) -> bool:
        try:
            unprotected_data = self._protector.decrypt(base64.urlsafe_b64decode(ensure_bytes(token)))
            data = msgspec.json.decode(unprotected_data)
            creation_time = datetime.fromtimestamp(data["creation_time"], tz=timezone.utc)
            expiration_time = normalize_datetime(creation_time + self.token_lifespan)

            if expiration_time < normalize_datetime(datetime.now(timezone.utc)):
                self.logger.error("Invalid expiration time.")
                return False

            if data["user_id"] != await manager.get_user_id(user):
                self.logger.error("User ID not equals.")
                return False

            if data["purpose"] != purpose:
                self.logger.error("Purpose not equals.")
                return False

            if manager.supports_user_security_stamp:
                is_equals_security_stamp: bool = data["stamp"] == await manager.get_security_stamp(user)
                if not is_equals_security_stamp:
                    self.logger.error("Security stamp not equals.")
                return is_equals_security_stamp

            stamp_is_empty = not bool(data["stamp"])
            if not stamp_is_empty:
                self.logger.error("Security stamp is not empty.")

            return stamp_is_empty
        except (TypeError, KeyError) as ex:
            self.logger.error(str(ex))
            return False
