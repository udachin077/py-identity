from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Generic

from pydentity.models import RoleT, UserT

if TYPE_CHECKING:
    from pydentity.security.claims import ClaimsPrincipal

__all__ = ["IUserClaimsPrincipalFactory"]


class IUserClaimsPrincipalFactory(Generic[UserT, RoleT], ABC):
    """Provides an abstraction for a factory to create a *ClaimsIdentity* from a user."""

    @abstractmethod
    async def create(self, user: UserT) -> ClaimsPrincipal:
        """Creates a *ClaimsPrincipal* from a user.

        :param user: The user to create a *ClaimsPrincipal* from.
        :return:
        """
