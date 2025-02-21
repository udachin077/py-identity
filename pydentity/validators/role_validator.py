from __future__ import annotations

from typing import TYPE_CHECKING, Generic

from pydentity.abc.validators import IRoleValidator
from pydentity.exc import ArgumentNoneError
from pydentity.identity_error_describer import IdentityErrorDescriber
from pydentity.identity_result import IdentityResult
from pydentity.models import RoleT
from pydentity.utils import is_none_or_whitespace

if TYPE_CHECKING:
    from pydentity.identity_error import IdentityError
    from pydentity.role_manager import RoleManager

__all__ = ["RoleValidator"]


class RoleValidator(IRoleValidator[RoleT], Generic[RoleT]):
    """Provides the default validation of roles."""

    __slots__ = ("_error_describer",)

    def __init__(self, error_describer: IdentityErrorDescriber | None = None) -> None:
        """Constructs a new instance of *RoleValidator[TRole]*.

        :param error_describer: The *IdentityErrorDescriber* used to provider error messages.
        """
        self._error_describer = error_describer or IdentityErrorDescriber()

    async def validate(self, manager: RoleManager[RoleT], role: RoleT) -> IdentityResult:
        if manager is None:
            raise ArgumentNoneError("manager")
        if role is None:
            raise ArgumentNoneError("role")

        errors: list[IdentityError] = []
        await self._validate_role_name(manager, role, errors)
        return IdentityResult.failed(*errors) if errors else IdentityResult.success()

    async def _validate_role_name(self, manager: RoleManager[RoleT], role: RoleT, errors: list[IdentityError]) -> None:
        role_name = await manager.get_role_name(role)

        if role_name is None or is_none_or_whitespace(role_name):
            errors.append(self._error_describer.InvalidRoleName(role_name))
            return

        if owner := await manager.find_by_name(role_name):
            if await manager.get_role_id(owner) != await manager.get_role_id(role):
                errors.append(self._error_describer.DuplicateRoleName(role_name))
