from __future__ import annotations

from typing import TYPE_CHECKING, Generic

import email_validator

from pydentity.abc.validators import IUserValidator
from pydentity.exc import ArgumentNoneError
from pydentity.identity_error_describer import IdentityErrorDescriber
from pydentity.identity_result import IdentityResult
from pydentity.models import UserT
from pydentity.utils import is_none_or_whitespace

if TYPE_CHECKING:
    from pydentity.identity_error import IdentityError
    from pydentity.user_manager import UserManager

__all__ = ["UserValidator"]


class UserValidator(IUserValidator[UserT], Generic[UserT]):
    """Provides validation builders for user classes."""

    __slots__ = ("_error_describer",)

    def __init__(self, error_describer: IdentityErrorDescriber | None = None) -> None:
        """Constructs a new instance of *UserValidator[TUser]*.

        :param error_describer: The *IdentityErrorDescriber* used to provider error messages.
        """
        self._error_describer = error_describer or IdentityErrorDescriber()

    async def validate(self, manager: UserManager[UserT], user: UserT) -> IdentityResult:
        if manager is None:
            raise ArgumentNoneError("manager")
        if user is None:
            raise ArgumentNoneError("user")

        errors: list[IdentityError] = []
        await self._validate_username(manager, user, errors)

        if manager.options.user.require_unique_email:
            await self._validate_email(manager, user, errors)

        return IdentityResult.failed(*errors) if errors else IdentityResult.success()

    async def _validate_username(
        self, manager: UserManager[UserT], user: UserT, errors: list[IdentityError]
    ) -> None:  # pragma: no cover
        username = await manager.get_username(user)
        if username is None or is_none_or_whitespace(username):
            errors.append(self._error_describer.InvalidUserName(username))
            return

        allowed_characters = manager.options.user.allowed_username_characters
        if allowed_characters and any(c not in allowed_characters for c in username):
            errors.append(self._error_describer.InvalidUserName(username))
            return

        owner = await manager.find_by_name(username)
        if owner and (await manager.get_user_id(owner) != await manager.get_user_id(user)):
            errors.append(self._error_describer.DuplicateUserName(username))

    async def _validate_email(
        self, manager: UserManager[UserT], user: UserT, errors: list[IdentityError]
    ) -> None:  # pragma: no cover
        email = await manager.get_email(user)
        if email is None or is_none_or_whitespace(email):
            errors.append(self._error_describer.InvalidEmail(email))
            return

        try:
            result = email_validator.validate_email(email, check_deliverability=False)
        except email_validator.EmailNotValidError:
            errors.append(self._error_describer.InvalidEmail(email))
            return

        allowed_email_domains = manager.options.user.allowed_email_domains
        if allowed_email_domains and (result.domain not in allowed_email_domains):
            errors.append(self._error_describer.InvalidDomain(result.domain))
            return

        owner = await manager.find_by_email(email)
        if owner and (await manager.get_user_id(owner) != await manager.get_user_id(user)):
            errors.append(self._error_describer.DuplicateEmail(email))
