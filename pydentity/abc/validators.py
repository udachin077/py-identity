from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic

from pydentity.models import RoleT, UserT

if TYPE_CHECKING:
    from pydentity.identity_result import IdentityResult
    from pydentity.role_manager import RoleManager
    from pydentity.user_manager import UserManager

__all__ = ["IPasswordValidator", "IRoleValidator", "IUserValidator"]


class IPasswordValidator(Generic[UserT], ABC):
    """Provides an abstraction for validating passwords."""

    @abstractmethod
    async def validate(self, manager: UserManager[UserT], password: str) -> IdentityResult:
        """Validates a password.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param password: The password to validate.
        :return:
        """


class IRoleValidator(Generic[RoleT], ABC):
    """Provides an abstraction for a validating a role."""

    @abstractmethod
    async def validate(self, manager: RoleManager[RoleT], role: RoleT) -> IdentityResult:
        """Validates a role.

        :param manager: The *RoleManager[TRole]* that can be used to retrieve role properties.
        :param role: The role to validate.
        :return:
        """


class IUserValidator(Generic[UserT], ABC):
    """Provides an abstraction for user validation."""

    @abstractmethod
    async def validate(self, manager: UserManager[UserT], user: UserT) -> IdentityResult:
        """Validates a user.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param user: The user to validate.
        :return:
        """
