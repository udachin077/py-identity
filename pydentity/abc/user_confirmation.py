from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic

from pydentity.models import UserT

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager

__all__ = ["IUserConfirmation"]


class IUserConfirmation(Generic[UserT], ABC):
    """Provides an abstraction for confirmation of user accounts."""

    @abstractmethod
    async def is_confirmed(self, manager: UserManager[UserT], user: UserT) -> bool:
        """Determines whether the specified user is confirmed.

        :param manager: The *UserManager[TUser]* that can be used to retrieve user properties.
        :param user: The user.
        :return: Whether the user is confirmed.
        """
