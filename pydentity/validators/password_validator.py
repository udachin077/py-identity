from __future__ import annotations

from typing import TYPE_CHECKING, Generic

from pydentity.abc.validators import IPasswordValidator
from pydentity.exc import ArgumentNoneError
from pydentity.identity_error_describer import IdentityErrorDescriber
from pydentity.identity_result import IdentityResult
from pydentity.models import UserT
from pydentity.utils import is_none_or_whitespace

if TYPE_CHECKING:
    from pydentity.identity_error import IdentityError
    from pydentity.user_manager import UserManager

__all__ = ["PasswordValidator"]


class PasswordValidator(IPasswordValidator[UserT], Generic[UserT]):
    """Provides the default password policy for Identity."""

    __slots__ = ("_error_describer",)

    def __init__(self, error_describer: IdentityErrorDescriber | None = None) -> None:
        """Constructs a new instance of *PasswordValidator[TUser]*.

        :param error_describer: The *IdentityErrorDescriber* used to provider error messages.
        """
        self._error_describer = error_describer or IdentityErrorDescriber()

    async def validate(self, manager: UserManager[UserT], password: str) -> IdentityResult:
        if manager is None:
            raise ArgumentNoneError("manager")
        if is_none_or_whitespace(password):
            raise ArgumentNoneError("password")

        options = manager.options.password
        errors: list[IdentityError] = []

        if options.required_length > len(password):
            errors.append(self._error_describer.PasswordTooShort(options.required_length))

        if options.required_digit and not any(c.isdigit() for c in password):
            errors.append(self._error_describer.PasswordRequiresDigit())

        if options.required_lowercase and not any(c.islower() for c in password):
            errors.append(self._error_describer.PasswordRequiresLower())

        if options.required_uppercase and not any(c.isupper() for c in password):
            errors.append(self._error_describer.PasswordRequiresUpper())

        if options.required_non_alphanumeric and all(c.isalnum() for c in password):
            errors.append(self._error_describer.PasswordRequiresNonAlphanumeric())

        required_unique_chars = options.required_unique_chars
        if required_unique_chars > 0 and len(set(password)) < required_unique_chars:
            errors.append(self._error_describer.PasswordRequiresUniqueChars(required_unique_chars))

        return IdentityResult.failed(*errors) if errors else IdentityResult.success()
