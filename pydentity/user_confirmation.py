from __future__ import annotations

from typing import TYPE_CHECKING, Generic

from pydentity.abc.user_confirmation import IUserConfirmation
from pydentity.models import UserT

if TYPE_CHECKING:
    from pydentity.user_manager import UserManager

__all__ = ["DefaultUserConfirmation"]


class DefaultUserConfirmation(IUserConfirmation[UserT], Generic[UserT]):
    """Default implementation of *IUserConfirmation[TUser]*."""

    async def is_confirmed(self, manager: UserManager[UserT], user: UserT) -> bool:
        return await manager.is_email_confirmed(user)
