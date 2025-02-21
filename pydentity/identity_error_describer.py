from pydentity.identity_error import IdentityError
from pydentity.resources import Resources

__all__ = ["IdentityErrorDescriber"]


class IdentityErrorDescriber:  # pragma: no cover
    """Service to enable localization for application facing builders errors."""

    __slots__ = ()

    @staticmethod
    def ConcurrencyFailure() -> IdentityError:
        return IdentityError(code="ConcurrencyFailure", description=Resources.ConcurrencyFailure)

    @staticmethod
    def DefaultError() -> IdentityError:
        return IdentityError(code="DefaultError", description=Resources.DefaultError)

    @staticmethod
    def DuplicateEmail(email: str) -> IdentityError:
        return IdentityError(code="DuplicateEmail", description=Resources.DuplicateEmail.format(email))

    @staticmethod
    def DuplicateRoleName(name: str) -> IdentityError:
        return IdentityError(code="DuplicateRoleName", description=Resources.DuplicateRoleName.format(name))

    @staticmethod
    def DuplicateUserName(name: str) -> IdentityError:
        return IdentityError(code="DuplicateUserName", description=Resources.DuplicateUserName.format(name))

    @staticmethod
    def InvalidEmail(email: str | None) -> IdentityError:
        return IdentityError(code="InvalidEmail", description=Resources.InvalidEmail.format(email))

    @staticmethod
    def InvalidRoleName(name: str | None) -> IdentityError:
        return IdentityError(code="InvalidRoleName", description=Resources.InvalidRoleName.format(name))

    @staticmethod
    def InvalidDomain(domain: str) -> IdentityError:
        return IdentityError(code="InvalidDomain", description=Resources.InvalidDomain.format(domain))

    @staticmethod
    def InvalidToken() -> IdentityError:
        return IdentityError(code="InvalidToken", description=Resources.InvalidToken)

    @staticmethod
    def InvalidUserName(name: str | None) -> IdentityError:
        return IdentityError(code="InvalidUserName", description=Resources.InvalidUserName.format(name))

    @staticmethod
    def LoginAlreadyAssociated() -> IdentityError:
        return IdentityError(code="InvalidUserName", description=Resources.LoginAlreadyAssociated)

    @staticmethod
    def NullSecurityStamp() -> IdentityError:
        return IdentityError(code="NullSecurityStamp", description=Resources.NullSecurityStamp)

    @staticmethod
    def PasswordMismatch() -> IdentityError:
        return IdentityError(code="PasswordMismatch", description=Resources.PasswordMismatch)

    @staticmethod
    def PasswordRequiresDigit() -> IdentityError:
        return IdentityError(code="PasswordRequiresDigit", description=Resources.PasswordRequiresDigit)

    @staticmethod
    def PasswordRequiresLower() -> IdentityError:
        return IdentityError(code="PasswordRequiresLower", description=Resources.PasswordRequiresLower)

    @staticmethod
    def PasswordRequiresNonAlphanumeric() -> IdentityError:
        return IdentityError(
            code="PasswordRequiresNonAlphanumeric",
            description=Resources.PasswordRequiresNonAlphanumeric,
        )

    @staticmethod
    def PasswordRequiresUpper() -> IdentityError:
        return IdentityError(code="PasswordRequiresUpper", description=Resources.PasswordRequiresUpper)

    @staticmethod
    def PasswordTooShort(length: int) -> IdentityError:
        return IdentityError(code="PasswordTooShort", description=Resources.PasswordTooShort.format(length))

    @staticmethod
    def PasswordRequiresUniqueChars(unique_chars: int) -> IdentityError:
        return IdentityError(
            code="PasswordRequiresUniqueChars",
            description=Resources.PasswordRequiresUniqueChars.format(unique_chars),
        )

    @staticmethod
    def RoleNotFound(name: str) -> IdentityError:
        return IdentityError(code="RoleNotFound", description=Resources.RoleNotFound.format(name))

    @staticmethod
    def RecoveryCodeRedemptionFailed() -> IdentityError:
        return IdentityError(
            code="RecoveryCodeRedemptionFailed",
            description=Resources.RecoveryCodeRedemptionFailed,
        )

    @staticmethod
    def UserAlreadyHasPassword() -> IdentityError:
        return IdentityError(code="UserAlreadyHasPassword", description=Resources.UserAlreadyHasPassword)

    @staticmethod
    def UserAlreadyInRole(name: str) -> IdentityError:
        return IdentityError(code="UserAlreadyInRole", description=Resources.UserAlreadyInRole.format(name))

    @staticmethod
    def UserLockedOut() -> IdentityError:
        return IdentityError(code="UserLockedOut", description=Resources.UserLockedOut)

    @staticmethod
    def UserLockoutNotEnabled() -> IdentityError:
        return IdentityError(code="UserLockoutNotEnabled", description=Resources.UserLockoutNotEnabled)

    @staticmethod
    def UserNameNotFound(name: str) -> IdentityError:
        return IdentityError(code="UserNameNotFound", description=Resources.UserNameNotFound.format(name))

    @staticmethod
    def UserNotInRole(name: str) -> IdentityError:
        return IdentityError(code="UserNotInRole", description=Resources.UserNotInRole.format(name))
