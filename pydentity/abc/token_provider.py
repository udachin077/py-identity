from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic

from pydentity.models import UserT

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager

__all__ = ["IUserTwoFactorTokenProvider"]


class IUserTwoFactorTokenProvider(Generic[UserT], ABC):
    """Provides an abstraction for token generators."""

    @abstractmethod
    async def generate(self, manager: UserManager[UserT], purpose: str, user: UserT) -> str:
        """Generates a token for the specified user and purpose.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param purpose: The purpose the token will be used for.
        :param user: The user a token should be generated for.
        :return: The token for the specified user and purpose.
        """

    @abstractmethod
    async def validate(self, manager: UserManager[UserT], purpose: str, token: str, user: UserT) -> bool:
        """Returns a flag indicating whether the specified token is valid for the given user and purpose.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param purpose: The purpose the token will be used for.
        :param token: The token to validate.
        :param user: The user a token should be validated for.
        :return: A flag indication the result of validating the token for the specified user and purpose.
            True if the token is valid, otherwise False.
        """

    @abstractmethod
    async def can_generate_two_factor(self, manager: UserManager[UserT], user: UserT) -> bool:
        """Checks if a two-factor authentication token can be generated for the specified user.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param user: The user a token could be generated for.
        :return: True if the user has an authenticator key set, otherwise False.
        """
