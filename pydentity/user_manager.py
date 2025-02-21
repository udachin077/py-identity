from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Final, Generic, cast, overload

from uuid_extensions import uuid7str

from pydentity.abc.stores import (
    IUserAuthenticationTokenStore,
    IUserAuthenticatorKeyStore,
    IUserClaimStore,
    IUserEmailStore,
    IUserLockoutStore,
    IUserLoginStore,
    IUserPasswordStore,
    IUserPersonalDataStore,
    IUserPhoneNumberStore,
    IUserRoleStore,
    IUserSecurityStampStore,
    IUserStore,
    IUserTwoFactorRecoveryCodeStore,
    IUserTwoFactorStore,
)
from pydentity.exc import (
    ArgumentNoneError,
    InvalidOperationError,
    NotSupportedError,
)
from pydentity.identity_error_describer import IdentityErrorDescriber
from pydentity.identity_options import IdentityOptions
from pydentity.identity_result import IdentityResult
from pydentity.models import UserT
from pydentity.password_hashers import Argon2PasswordHasher, PasswordVerificationResult
from pydentity.resources import Resources
from pydentity.rfc6238_authentication_service import generate_key, get_provisioning_uri
from pydentity.security.claims import Claim, ClaimsPrincipal, ClaimTypes
from pydentity.utils import ensure_bytes, is_none_or_whitespace, normalize_datetime

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pydentity.abc.lookup_normalizer import ILookupNormalizer
    from pydentity.abc.password_hasher import IPasswordHasher
    from pydentity.abc.token_provider import IUserTwoFactorTokenProvider
    from pydentity.abc.validators import IPasswordValidator, IUserValidator
    from pydentity.identity_error import IdentityError
    from pydentity.user_login_info import UserLoginInfo

__all__ = ["UserManager"]


class UserManager(Generic[UserT]):
    """Provides the APIs for managing user in a persistence stores."""

    __slots__ = (
        "_token_providers",
        "error_describer",
        "key_normalizer",
        "logger",
        "options",
        "password_hasher",
        "password_validators",
        "store",
        "user_validators",
    )

    RESET_PASSWORD_TOKEN_PURPOSE: Final[str] = "ResetPassword"
    """The data protection purpose used for the reset password related methods."""
    CHANGE_EMAIL_TOKEN_PURPOSE: Final[str] = "ChangeEmail"
    """The data protection purpose used for the change email methods."""
    CHANGE_PHONE_NUMBER_TOKEN_PURPOSE: Final[str] = "ChangePhoneNumber"
    """The data protection purpose used for the change phone number methods."""
    CONFIRM_EMAIL_TOKEN_PURPOSE: Final[str] = "EmailConfirmation"
    """The data protection purpose used for the email confirmation related methods."""
    CONFIRM_PHONE_NUMBER_TOKEN_PURPOSE: Final[str] = "PhoneNumberConfirmation"
    """The data protection purpose used for the phone number confirmation related methods."""

    def __init__(
        self,
        user_store: IUserStore[UserT],
        options: IdentityOptions | None = None,
        password_hasher: IPasswordHasher[UserT] | None = None,
        password_validators: Iterable[IPasswordValidator[UserT]] | None = None,
        user_validators: Iterable[IUserValidator[UserT]] | None = None,
        key_normalizer: ILookupNormalizer | None = None,
        error_describer: IdentityErrorDescriber | None = None,
    ) -> None:
        """Constructs a new instance of *UserManager[UserT]*.

        :param user_store: The persistence store the manager will operate over.
        :param options:
        :param password_hasher: The password hashing implementation to use when saving passwords.
        :param password_validators: A collection of *IPasswordValidator[UserT]* to validate passwords against.
        :param user_validators: A collection of *IUserValidator[UserT]* to validate auth against.
        :param key_normalizer: The *ILookupNormalizer* to use when generating index keys for auth.
        :param error_describer: The *IdentityErrorDescriber* used to provider error messages.
        """
        if not user_store:
            raise ArgumentNoneError("user_store")

        self.store = user_store
        """Gets or sets the persistence store the manager operates over."""
        self.options: IdentityOptions = options or IdentityOptions()
        """Gets or sets *IdentityOptions* used to configure PyIdentity."""
        self.password_hasher: IPasswordHasher[UserT] = password_hasher or Argon2PasswordHasher()
        """Gets or sets *IPasswordHasher[UserT]* used to hash passwords."""
        self.password_validators = password_validators
        """Gets or sets *IPasswordValidator[UserT]* used to validate passwords."""
        self.user_validators = user_validators
        """Gets or sets *IUserValidator[UserT]* used to validate users."""
        self.key_normalizer = key_normalizer
        """Gets or sets *ILookupNormalizer* used to normalize things like usernames and emails."""
        self.error_describer: IdentityErrorDescriber = error_describer or IdentityErrorDescriber()
        """Gets or sets *IdentityErrorDescriber* used to generate error messages."""
        self.logger = logging.getLogger("PyIdentity.UserManager")
        """Gets or sets logger used to log messages from the manager."""
        self._token_providers: dict[str, IUserTwoFactorTokenProvider[UserT]] = self.options.tokens.provider_map
        """The token providers."""

    @property
    def supports_user_authentication_tokens(self) -> bool:
        """Gets a flag indicating whether the backing user store supports authentication tokens.

        :return: *True* if the backing user store supports authentication tokens, otherwise *False*.
        """
        return issubclass(type(self.store), IUserAuthenticationTokenStore)

    @property
    def supports_user_authenticator_key(self) -> bool:
        """Gets a flag indicating whether the backing user store supports a user authenticator.

        :return: *True* if the backing user store supports a user authenticator, otherwise *False*.
        """
        return issubclass(type(self.store), IUserAuthenticatorKeyStore)

    @property
    def supports_user_two_factor_recovery_codes(self) -> bool:
        """Gets a flag indicating whether the backing user store supports recovery codes.

        :return: *True* if the backing user store supports a user authenticator, otherwise *False*.
        """
        return issubclass(type(self.store), IUserTwoFactorRecoveryCodeStore)

    @property
    def supports_user_two_factor(self) -> bool:
        """Gets a flag indicating whether the backing user store supports two-factor authentication.

        :return: *True* if the backing user store supports user two-factor authentication, otherwise *False*.
        """
        return issubclass(type(self.store), IUserTwoFactorStore)

    @property
    def supports_user_password(self) -> bool:
        """Gets a flag indicating whether the backing user store supports user passwords.

        :return: *True* if the backing user store supports user passwords, otherwise *False*.
        """
        return issubclass(type(self.store), IUserPasswordStore)

    @property
    def supports_user_security_stamp(self) -> bool:
        """Gets a flag indicating whether the backing user store supports security stamps.

        :return: *True* if the backing user store supports user security stamps, otherwise *False*.
        """
        return issubclass(type(self.store), IUserSecurityStampStore)

    @property
    def supports_user_role(self) -> bool:
        """Gets a flag indicating whether the backing user store supports user roles.

        :return: *True* if the backing user store supports user roles, otherwise *False*.
        """
        return issubclass(type(self.store), IUserRoleStore)

    @property
    def supports_user_login(self) -> bool:
        """Gets a flag indicating whether the backing user store supports external logins.

        :return: *True* if the backing user store supports user roles, otherwise *False*.
        """
        return issubclass(type(self.store), IUserLoginStore)

    @property
    def supports_user_email(self) -> bool:
        """Gets a flag indicating whether the backing user store supports user emails.

        :return: *True* if the backing user store supports user emails, otherwise *False*.
        """
        return issubclass(type(self.store), IUserEmailStore)

    @property
    def supports_user_phone_number(self) -> bool:
        """Gets a flag indicating whether the backing user store supports user telephone numbers.

        :return: *True* if the backing user store supports user phone numbers, otherwise *False*.
        """
        return issubclass(type(self.store), IUserPhoneNumberStore)

    @property
    def supports_user_claim(self) -> bool:
        """Gets a flag indicating whether the backing user store supports user claims.

        :return: *True* if the backing user store supports user claims, otherwise *False*.
        """
        return issubclass(type(self.store), IUserClaimStore)

    @property
    def supports_user_lockout(self) -> bool:
        """Gets a flag indicating whether the backing user store supports user lock-outs.

        :return: *True* if the backing user store supports user lock-outs, otherwise *False*.
        """
        return issubclass(type(self.store), IUserLockoutStore)

    @property
    def supports_user_personal_data(self) -> bool:
        """Gets a flag indicating whether the backing user store supports user personal data.

        :return: *True* if the backing user store supports user personal data, otherwise *False*.
        """
        return issubclass(type(self.store), IUserPersonalDataStore)

    async def all(self) -> list[UserT]:
        """Get all users from this store.

        :return: Returns a list of *UserT* objects.
        """
        return await self.store.all()

    @overload
    async def get_username(self, user: UserT) -> str | None: ...

    @overload
    async def get_username(self, user: ClaimsPrincipal) -> str | None: ...

    async def get_username(self, user: ClaimsPrincipal | UserT) -> str | None:
        """Gets the username for the specified user.

        :param user: The *UserT* or *ClaimsPrincipal* instance.
        :return: Returns name or the Name claim value if present, otherwise None.
        """
        if user is None:
            raise ArgumentNoneError("user")

        if isinstance(user, ClaimsPrincipal):
            return user.find_first_value(ClaimTypes.Name)
        return await self.store.get_username(user)

    async def set_username(self, user: UserT, username: str | None = None) -> IdentityResult:
        """Sets the given username for the specified user.

        :param user: The user whose name should be set.
        :param username: The username to set.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        await self.store.set_username(user, username)
        await self._update_security_stamp_internal(user)
        return await self._update_user(user)

    @overload
    async def get_user_id(self, user: UserT) -> str | None: ...

    @overload
    async def get_user_id(self, user: ClaimsPrincipal) -> str | None: ...

    async def get_user_id(self, user: ClaimsPrincipal | UserT) -> str | None:
        """Gets the user identifier for the specified user.

        :param user: The *UserT* or *ClaimsPrincipal* instance.
        :return: Returns the ID or User ID claim value if present otherwise returns None.
        """
        if user is None:
            raise ArgumentNoneError("user")

        if isinstance(user, ClaimsPrincipal):
            return user.find_first_value(ClaimTypes.NameIdentifier)

        return await self.store.get_user_id(user)

    async def get_user(self, principal: ClaimsPrincipal) -> UserT | None:
        """Returns the user corresponding to the *IdentityOptions.claims_identity.user_id_claim_type* claim in
        the principal or *None*.

        :param principal: The *ClaimsPrincipal* instance.
        :return:
        """
        if principal is None:
            raise ArgumentNoneError("principal")

        if user_id := await self.get_user_id(principal):
            return await self.find_by_id(user_id)
        return None

    @staticmethod
    def generate_concurrency_stamp(user: UserT) -> str:
        """Generates a value suitable for use in concurrency tracking.

        :param user: The user to generate the stamp for.
        :return:
        """
        return uuid7str()  # type: ignore

    @overload
    async def create(self, user: UserT) -> IdentityResult: ...

    @overload
    async def create(self, user: UserT, password: str) -> IdentityResult: ...

    async def create(self, user: UserT, password: str | None = None) -> IdentityResult:
        """Create the specified user in the backing stores.

        :param user: The user to create.
        :param password: The password for the user to hash and store.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        if password:
            result = await self._update_password_hash(self._get_password_store(), user, password)
            if not result.succeeded:
                return result

        await self._update_security_stamp_internal(user)

        result = await self._validate_user(user)
        if not result.succeeded:
            return result

        if self.options.lockout.allowed_for_new_user and self.supports_user_lockout:
            await self._get_user_lockout_store().set_lockout_enabled(user, True)

        await self.update_normalized_username(user)
        await self.update_normalized_email(user)
        return await self.store.create(user)

    async def update(self, user: UserT) -> IdentityResult:
        """Updates the specified user in the backing stores.

        :param user: The user to update.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self._update_user(user)

    async def delete(self, user: UserT) -> IdentityResult:
        """Deletes the specified user from the backing stores.

        :param user: The user to delete.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self.store.delete(user)

    async def find_by_id(self, user_id: str) -> UserT | None:
        """Finds and returns a user, if any, who has the specified *user_id*.

        :param user_id: The user ID to search for.
        :return: Returns the *UserT* matching the specified *user_id* if it exists.
        """
        if user_id is None:
            raise ArgumentNoneError("user_id")

        return await self.store.find_by_id(user_id)

    async def find_by_name(self, username: str) -> UserT | None:
        """Finds and returns a user, if any, who has the specified *username*.

        :param username: The username to search for.
        :return: Returns the *UserT* matching the specified *username* if it exists.
        """
        if not username:
            raise ArgumentNoneError("username")

        normalized_username = self._normalize_name(username)
        return await self.store.find_by_name(normalized_username)  # type:ignore[arg-type]

    async def update_normalized_username(self, user: UserT) -> None:
        """Updates the normalized username for the specified user.

        :param user: The user whose username should be normalized and updated.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        normalized_username = self._normalize_name(await self.store.get_username(user))
        await self.store.set_normalized_username(user, normalized_username)

    async def check_password(self, user: UserT, password: str) -> bool:
        """Returns a flag indicating whether the given password is valid for the specified user.

        :param user: The user whose password should be validated.
        :param password: The password to validate.
        :return: *True* if the specified *password* matches the one store for the *user*, otherwise *False*.
        """
        if user is None:
            return False

        store = self._get_password_store()
        result = await self._verify_password(store, user, password)

        if result == PasswordVerificationResult.SuccessRehashNeeded:
            await self._update_password_hash(store, user, password, validate_password=False)
            await self._update_user(user)

        success = result != PasswordVerificationResult.Failed
        if not success:
            self.logger.warning("Invalid password for user.")
        return success

    async def has_password(self, user: UserT) -> bool:
        """Gets a flag indicating whether the specified user has a password.

        :param user: The user to return a flag for, indicating whether they have a password or not.
        :return: *True* if the specified user has a password, otherwise *False*.
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self._get_password_store().has_password(user)

    async def add_password(self, user: UserT, password: str) -> IdentityResult:
        """Adds the password to the specified user only if the user does not already have a password.

        :param user: The user whose password should be set.
        :param password: The password to set.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        store = self._get_password_store()

        if await store.get_password_hash(user):
            self.logger.warning("User already has a password.")
            return IdentityResult.failed(self.error_describer.UserAlreadyHasPassword())

        result = await self._update_password_hash(store, user, password)
        if not result.succeeded:
            return result
        return await self._update_user(user)

    async def change_password(self, user: UserT, current_password: str, new_password: str) -> IdentityResult:
        """Changes a user's password after confirming the specified *current_password* is correct.

        :param user: The user whose password should be set.
        :param current_password: The current password to validate before changing.
        :param new_password: The new password to set for the specified user.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        store = self._get_password_store()

        if await self._verify_password(store, user, current_password) != PasswordVerificationResult.Failed:
            result = await self._update_password_hash(store, user, new_password)
            if not result.succeeded:
                return result
            return await self._update_user(user)

        self.logger.warning("Change password failed for user.")
        return IdentityResult.failed(self.error_describer.PasswordMismatch())

    async def remove_password(self, user: UserT) -> IdentityResult:
        """Remove the password for the specified user.

        :param user: The user whose password should be removed.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        await self._update_password_hash(self._get_password_store(), user, None, validate_password=False)
        return await self._update_user(user)

    async def _verify_password(
        self, password_store: IUserPasswordStore[UserT], user: UserT, password: str
    ) -> PasswordVerificationResult:
        """Returns a *PasswordVerificationResult* indicating the result of a password hash comparison.

        :param password_store: The store containing a user's password.
        :param user: The user whose password should be verified.
        :param password: The password to verify.
        :return:
        """
        hash_ = await password_store.get_password_hash(user)
        if not hash_:
            return PasswordVerificationResult.Failed
        return self.password_hasher.verify_hashed_password(user, hash_, password)

    async def get_security_stamp(self, user: UserT) -> str:
        """Get the security stamp for the specified user.

        :param user: The user whose security stamp should be set.
        :return:
        :raise InvalidOperationError: if the specified user does not have a security stamp.
        """
        if user is None:
            raise ArgumentNoneError("user")

        if stamp := await self._get_security_store().get_security_stamp(user):
            return stamp
        self.logger.debug("`get_security_stamp` for user failed because stamp was None.")
        raise InvalidOperationError(Resources.NullSecurityStamp)

    async def update_security_stamp(self, user: UserT) -> IdentityResult:
        """Regenerates the security stamp for the specified user.

        :param user: The user whose security stamp should be regenerated.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        await self._update_security_stamp_internal(user)
        return await self._update_user(user)

    async def generate_password_reset_token(self, user: UserT) -> str:
        """Generates a password reset token for the specified user, using the configured password reset token provider.

        :param user: The user to generate a password reset token for.
        :return: A password reset token for the specified user.
        """
        return await self.generate_user_token(
            user,
            self.options.tokens.password_reset_token_provider,
            self.RESET_PASSWORD_TOKEN_PURPOSE,
        )

    async def reset_password(self, user: UserT, token: str, new_password: str) -> IdentityResult:
        """Resets the user's password to the specified *new_password* after validating the given password reset token.

        :param user: The user whose password should be reset.
        :param token: The password reset token to verify.
        :param new_password: The new password to set if reset token verification succeeds.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        if not await self.verify_user_token(
            user,
            self.options.tokens.password_reset_token_provider,
            self.RESET_PASSWORD_TOKEN_PURPOSE,
            token,
        ):
            return IdentityResult.failed(self.error_describer.InvalidToken())

        result = await self._update_password_hash(self._get_password_store(), user, new_password)
        if not result.succeeded:
            return result
        return await self._update_user(user)

    async def find_by_login(self, login_provider: str, provider_key: str) -> UserT | None:
        """Retrieves the user associated with the specified external login provider and login provider key.

        :param login_provider: The login provider who provided the provider_key.
        :param provider_key: The key provided by the login_provider to identify a user.
        :return: Returns the user, if any matched the specified login provider and key, or None otherwise.
        """
        if not login_provider:
            raise ArgumentNoneError("login_provider")
        if not provider_key:
            raise ArgumentNoneError("provider_key")

        return await self._get_login_store().find_by_login(login_provider, provider_key)

    async def remove_login(self, user: UserT, login_provider: str, provider_key: str) -> IdentityResult:
        """Attempts to remove the provided external login information from the specified user.
        And returns a flag indicating whether the removal succeeds or not.

        :param user: The user to remove the login information from.
        :param login_provider: The login provides that information should be removed.
        :param provider_key: The key given by the external login provider for the specified user.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not login_provider:
            raise ArgumentNoneError("login_provider")
        if not provider_key:
            raise ArgumentNoneError("provider_key")

        store = self._get_login_store()
        await store.remove_login(user, login_provider, provider_key)
        await self._update_security_stamp_internal(user)
        return await self._update_user(user)

    async def add_login(self, user: UserT, login: UserLoginInfo) -> IdentityResult:
        """Adds an external *UserLoginInfo* to the specified user.

        :param user: The user to add the login to.
        :param login: The external *UserLoginInfo* to add to the specified user.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not login:
            raise ArgumentNoneError("login")

        if await self.find_by_login(login.login_provider, login.provider_key):
            self.logger.warning("`add_login` for user failed because it was already associated with another user.")
            return IdentityResult.failed(self.error_describer.LoginAlreadyAssociated())

        await self._get_login_store().add_login(user, login)
        return await self._update_user(user)

    async def get_logins(self, user: UserT) -> list[UserLoginInfo]:
        """Retrieves the associated logins for the specified user.

        :param user: The user whose associated logins to retrieve.
        :return: A list of *UserLoginInfo* for the specified user.
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self._get_login_store().get_logins(user)

    async def add_claims(self, user: UserT, *claims: Claim) -> IdentityResult:
        """Adds the specified claims to the user.

        :param user: The user to add the claim to.
        :param claims: The claims to add.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not claims:
            raise ArgumentNoneError("claims")

        await self._get_claim_store().add_claims(user, *claims)
        return await self._update_user(user)

    async def replace_claim(self, user: UserT, claim: Claim, new_claim: Claim) -> IdentityResult:
        """Replaces the given *claim* on the specified user with the *new_claim*.

        :param user: The user to replace the claim on.
        :param claim: The claim to replace.
        :param new_claim: The claim to replace. The new claim to replace the existing claim with.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")
        if claim is None:
            raise ArgumentNoneError("claim")
        if new_claim is None:
            raise ArgumentNoneError("new_claim")

        await self._get_claim_store().replace_claim(user, claim, new_claim)
        return await self._update_user(user)

    async def remove_claims(self, user: UserT, *claims: Claim) -> IdentityResult:
        """Removes the specified claims from the given user.

        :param user: The user to remove the specified claims from.
        :param claims: A collection of *Claim*'s to be removed.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not claims:
            raise ArgumentNoneError("claims")

        await self._get_claim_store().remove_claims(user, *claims)
        return await self._update_user(user)

    async def get_claims(self, user: UserT) -> list[Claim]:
        """Gets a list of *Claim*'s to be belonging to the specified user.

        :param user: The user whose claims to retrieve.
        :return: A list of *Claim*'s to be belonging to the specified user.
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self._get_claim_store().get_claims(user)

    async def get_users_for_claim(self, claim: Claim) -> list[UserT]:
        """Returns a list of auth from the user store who have the specified claim.

        :param claim: The claim to look for.
        :return: A list of *UserT* who have the specified claim.
        """
        return await self._get_claim_store().get_users_for_claim(claim)

    async def add_to_roles(self, user: UserT, *roles: str) -> IdentityResult:
        """Add the specified user to the named roles.

        :param user: The user to add to the named roles.
        :param roles: The name of the role to add the user to.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not roles:
            raise ArgumentNoneError("roles")

        store = self._get_user_role_store()

        for normalized_role in {self._normalize_name(role) for role in roles if role is not None}:
            if await store.is_in_role(user, normalized_role):  # type: ignore[arg-type]
                self.logger.debug("User is already in role %s.", normalized_role)
                return IdentityResult.failed(self.error_describer.UserAlreadyInRole(normalized_role))  # type: ignore[arg-type]

            await store.add_to_role(user, normalized_role)  # type: ignore[arg-type]

        return await self._update_user(user)

    async def remove_from_roles(self, user: UserT, *roles: str) -> IdentityResult:
        """Removes the specified user from the named roles.

        :param user: The user to remove from the named roles.
        :param roles: The name of the roles to remove the user from.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not roles:
            raise ArgumentNoneError("roles")

        store = self._get_user_role_store()

        for normalized_role in {self._normalize_name(role) for role in roles if role is not None}:
            if not await store.is_in_role(user, normalized_role):  # type: ignore[arg-type]
                self.logger.debug("User is not in role %s.", normalized_role)
                return IdentityResult.failed(self.error_describer.UserNotInRole(normalized_role))  # type: ignore[arg-type]

            await store.remove_from_role(user, normalized_role)  # type: ignore[arg-type]

        return await self._update_user(user)

    async def get_roles(self, user: UserT) -> list[str]:
        """Gets a list of role names the specified user belongs to.

        :param user: The user whose role names to retrieve.
        :return: A list of role names.
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self._get_user_role_store().get_roles(user)

    async def is_in_role(self, user: UserT, role: str) -> bool:
        """Returns a flag indicating whether the specified user is a member of the given named role.

        :param user: The user whose role membership should be checked.
        :param role: The name of the role to be checked.
        :return: A flag indicating whether the specified user is a member of the given named role.
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not role:
            raise ArgumentNoneError("role")

        return await self._get_user_role_store().is_in_role(user, self._normalize_name(role))  # type: ignore

    async def get_users_in_role(self, role: str) -> list[UserT]:
        """Returns a list of auth from the user stores who are members of the specified *role*.

        :param role: The name of the role whose auth should be returned.
        :return: A list of *UserT* who are members of the specified *role*.
        """
        if not role:
            raise ArgumentNoneError("role")

        return await self._get_user_role_store().get_users_in_role(self._normalize_name(role))  # type: ignore

    async def get_email(self, user: UserT) -> str | None:
        """Gets the email address for the specified user.

        :param user: The user whose email should be returned.
        :return: The email address for the specified user.
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self._get_email_store().get_email(user)

    async def set_email(self, user: UserT, email: str | None = None) -> IdentityResult:
        """Sets the email address for a user.

        :param user: The user whose email should be set.
        :param email: The email to set.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        store = self._get_email_store()
        await store.set_email(user, email)
        await store.set_email_confirmed(user, False)
        await self._update_security_stamp_internal(user)
        return await self._update_user(user)

    async def find_by_email(self, email: str) -> UserT | None:
        """Gets the user, if any, associated with the normalized value of the specified email address.

        :param email: The email address to return the user for.
        :return: Returns the *UserT* if found, *None* otherwise.
        """
        if not email:
            raise ArgumentNoneError("email")

        return await self._get_email_store().find_by_email(self._normalize_email(email))  # type: ignore

    async def update_normalized_email(self, user: UserT) -> None:
        """Updates the normalized email for the specified user.

        :param user: The user whose email address should be normalized and updated.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        store = self._get_email_store()
        normalized_email = self._normalize_email(await store.get_email(user))
        await store.set_normalized_email(user, normalized_email)

    async def generate_email_confirmation_token(self, user: UserT) -> str:
        """Generates an email confirmation token for the specified user.

        :param user: The user to generate an email confirmation token for.
        :return: An email confirmation token for the specified user.
        """
        return await self.generate_user_token(
            user,
            self.options.tokens.email_confirmation_token_provider,
            self.CONFIRM_EMAIL_TOKEN_PURPOSE,
        )

    async def confirm_email(self, user: UserT, token: str) -> IdentityResult:
        """Validates that an email confirmation token matches the specified user.

        :param user: The user to validate the token against.
        :param token: The email confirmation token to validate.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        if not await self.verify_user_token(
            user,
            self.options.tokens.email_confirmation_token_provider,
            self.CONFIRM_EMAIL_TOKEN_PURPOSE,
            token,
        ):
            self.logger.warning("Confirmation email for user failed with invalid token.")
            return IdentityResult.failed(self.error_describer.InvalidToken())

        await self._get_email_store().set_email_confirmed(user, True)
        return await self._update_user(user)

    async def is_email_confirmed(self, user: UserT) -> bool:
        """Gets a flag indicating whether the email address for the specified user has been verified.

        :param user: The user whose email confirmation status should be returned.
        :return: *True* if the email address is verified, *False* otherwise.
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self._get_email_store().get_email_confirmed(user)

    async def generate_change_email_token(self, user: UserT, new_email: str) -> str:
        """Generates an email change token for the specified user.

        :param user: The user to generate an email change token for.
        :param new_email: The new email address.
        :return: An email change token for the specified user.
        """
        return await self.generate_user_token(
            user,
            self.options.tokens.change_email_token_provider,
            f"{self.CHANGE_EMAIL_TOKEN_PURPOSE}:{new_email}",
        )

    async def change_email(self, user: UserT, new_email: str, token: str) -> IdentityResult:
        """Updates an auth emails if the specified email change token is valid for the user.

        :param user: The user whose email should be updated.
        :param new_email: The new email address.
        :param token: The change email token to be verified.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        if not await self.verify_user_token(
            user,
            self.options.tokens.change_email_token_provider,
            f"{self.CHANGE_EMAIL_TOKEN_PURPOSE}:{new_email}",
            token,
        ):
            self.logger.warning("Change email for user failed with invalid token.")
            return IdentityResult.failed(self.error_describer.InvalidToken())

        store = self._get_email_store()
        await store.set_email(user, new_email)
        await store.set_email_confirmed(user, True)
        await self._update_security_stamp_internal(user)
        return await self._update_user(user)

    async def get_phone_number(self, user: UserT) -> str | None:
        """Gets the phone number for the specified user.

        :param user: The user whose telephone number should be retrieved.
        :return: A phone number for the specified user.
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self._get_phone_number_store().get_phone_number(user)

    async def set_phone_number(self, user: UserT, phone_number: str | None = None) -> IdentityResult:
        """Sets the phone number for the specified user.

        :param user: The user whose phone number to set.
        :param phone_number: The phone number to set.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        store = self._get_phone_number_store()
        await store.set_phone_number(user, phone_number)
        await store.set_phone_number_confirmed(user, False)
        await self._update_security_stamp_internal(user)
        return await self._update_user(user)

    async def is_phone_number_confirmed(self, user: UserT) -> bool:
        """Gets a flag indicating whether the specified auth telephone number has been confirmed.

        :param user: The user to return a flag for, indicating whether their telephone number is confirmed.
        :return: *True* if the phone number is confirmed, *False* otherwise.
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self._get_phone_number_store().get_phone_number_confirmed(user)

    async def generate_phone_number_confirmation_token(self, user: UserT) -> str:
        """Generates an email confirmation token for the specified user.

        :param user: The user to generate an email confirmation token for.
        :return: A phone number confirmation token for the specified user.
        """
        return await self.generate_user_token(
            user,
            self.options.tokens.phone_number_confirmation_token_provider,
            self.CONFIRM_PHONE_NUMBER_TOKEN_PURPOSE,
        )

    async def confirm_phone_number(self, user: UserT, token: str) -> IdentityResult:
        """Validates that a phone number confirmation token matches the specified user.

        :param user: The user to validate the token against.
        :param token: The phone number confirmation token to validate.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        if not await self.verify_user_token(
            user,
            self.options.tokens.phone_number_confirmation_token_provider,
            self.CONFIRM_PHONE_NUMBER_TOKEN_PURPOSE,
            token,
        ):
            self.logger.warning("Confirmation phone number for user failed with invalid token.")
            return IdentityResult.failed(self.error_describer.InvalidToken())

        await self._get_phone_number_store().set_phone_number_confirmed(user, True)
        return await self._update_user(user)

    async def generate_change_phone_number_token(self, user: UserT, phone_number: str) -> str:
        """Generates a telephone number change token for the specified user.

        :param user: The user to generate a telephone number token for.
        :param phone_number: The new phone number the validation token should be sent to.
        :return: A phone number change token for the specified user.
        """
        return await self.generate_user_token(
            user,
            self.options.tokens.change_phone_number_token_provider,
            f"{self.CHANGE_PHONE_NUMBER_TOKEN_PURPOSE}:{phone_number}",
        )

    async def change_phone_number(self, user: UserT, phone_number: str, token: str) -> IdentityResult:
        """Sets the phone number for the specified user if the specified change token is valid.

        :param user: The user whose phone number to set.
        :param phone_number: The phone number to set.
        :param token: The phone number confirmation token to validate.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not phone_number:
            raise ArgumentNoneError("phone_number")

        if not await self.verify_user_token(
            user,
            self.options.tokens.change_phone_number_token_provider,
            f"{self.CHANGE_PHONE_NUMBER_TOKEN_PURPOSE}:{phone_number}",
            token,
        ):
            self.logger.warning("Change phone number for user failed with invalid token.")
            return IdentityResult.failed(self.error_describer.InvalidToken())

        store = self._get_phone_number_store()
        await store.set_phone_number(user, phone_number)
        await store.set_phone_number_confirmed(user, True)
        await self._update_security_stamp_internal(user)
        return await self._update_user(user)

    async def verify_user_token(self, user: UserT, token_provider: str, purpose: str, token: str) -> bool:
        """Returns a flag indicating whether the specified token is valid for the given user and purpose.

        :param user: The user to validate the token against.
        :param token_provider: The token provider used to generate the token.
        :param purpose: The purpose of the token should be generated for.
        :param token: The token to validate.
        :return: *True* if the token is valid, *False* otherwise.
        :raise NotSupportedError: if *token_provider* is not supported.
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not token_provider:
            raise ArgumentNoneError("token_provider")

        if provider := self._token_providers.get(token_provider):
            result = await provider.validate(self, purpose, token, user)
            if not result:
                self.logger.error("Verify token failed with purpose: %s for user.", purpose)
            return result

        raise NotSupportedError(Resources.FormatNoTokenProvider(token_provider))

    async def generate_user_token(self, user: UserT, token_provider: str, purpose: str) -> str:
        """Generates a token for the given user and purpose.

        :param user: The user the token will be for.
        :param token_provider: The provider which will generate the token.
        :param purpose: The purpose of the token will be for.
        :return: A token for the given user and purpose.
        :raise NotSupportedError: if *token_provider* is not supported.
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not token_provider:
            raise ArgumentNoneError("token_provider")

        if provider := self._token_providers.get(token_provider):
            return await provider.generate(self, purpose, user)

        raise NotSupportedError(Resources.FormatNoTokenProvider(token_provider))

    async def get_valid_two_factor_providers(self, user: UserT) -> list[str]:
        """Gets a list of valid two-factor token providers for the specified user.

        :param user: The user the whose two-factor authentication providers will be returned.
        :return: A list of two-factor token providers for the specified user.
        """
        if user is None:
            raise ArgumentNoneError("user")

        two_factor_token_providers: list[str] = []
        for token_provider_key, token_provider in self._token_providers.items():
            if await token_provider.can_generate_two_factor(self, user):
                two_factor_token_providers.append(token_provider_key)

        return two_factor_token_providers

    async def verify_two_factor_token(self, user: UserT, token_provider: str, token: str) -> bool:
        """Verifies the specified two-factor authentication token against the user.

        :param user: The user the token is supposed to be for.
        :param token_provider: The provider which will verify the token.
        :param token: The token to verify.
        :return: *True* if the token is valid, *False* otherwise.
        :raise NotSupportedError: if *token_provider* is not supported.
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not token_provider:
            raise ArgumentNoneError("token_provider")

        if provider := self._token_providers.get(token_provider):
            result = await provider.validate(self, "TwoFactor", token, user)
            if not result:
                self.logger.error("Verify two-factor token failed for user.")
            return result

        raise NotSupportedError(Resources.FormatNoTokenProvider(token_provider))

    async def generate_two_factor_token(self, user: UserT, token_provider: str) -> str:
        """Gets a two-factor authentication token for the specified user.

        :param user: The user the token is supposed to be for.
        :param token_provider: The provider which will verify the token.
        :return: A two-factor authentication token for the specified user.
        :raise NotSupportedError: if *token_provider* is not supported.
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not token_provider:
            raise ArgumentNoneError("token_provider")

        if provider := self._token_providers.get(token_provider):
            return await provider.generate(self, "TwoFactor", user)

        raise NotSupportedError(Resources.FormatNoTokenProvider(token_provider))

    async def get_two_factor_enabled(self, user: UserT) -> bool:
        """Returns a flag indicating whether the specified user has two-factor authentication enabled or not.

        :param user: The user whose two-factor authentication enabled status should be retrieved.
        :return: *True* if the user is two-factor authentication enabled, *False* otherwise.
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self._get_two_factor_store().get_two_factor_enabled(user)

    async def set_two_factor_enabled(self, user: UserT, enabled: bool) -> IdentityResult:
        """Sets a flag indicating whether the specified user has two-factor authentication enabled or not.

        :param user: The user whose two-factor authentication enabled status should be set.
        :param enabled: A flag indicating whether the specified *user* has two-factor authentication enabled.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        await self._get_two_factor_store().set_two_factor_enabled(user, enabled)
        await self._update_security_stamp_internal(user)
        return await self._update_user(user)

    async def is_locked_out(self, user: UserT) -> bool:
        """Returns a flag indicating whether the specified user is locked out.

        :param user: The user whose locked out status should be retrieved.
        :return: *True* if the user is locked out, *False* otherwise.
        """
        if user is None:
            raise ArgumentNoneError("user")

        store = self._get_user_lockout_store()

        if not await store.get_lockout_enabled(user):
            return False

        lockout_end = await store.get_lockout_end_date(user)
        if lockout_end is None:
            return False

        return lockout_end >= normalize_datetime(datetime.now(timezone.utc))

    async def set_lockout_enable(self, user: UserT, enabled: bool) -> IdentityResult:
        """Sets a flag indicating whether the specified user is locked out.

        :param user: The user whose locked out status should be set.
        :param enabled: Flag indicating whether the user is locked out or not.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        await self._get_user_lockout_store().set_lockout_enabled(user, enabled)
        return await self._update_user(user)

    async def get_lockout_enable(self, user: UserT) -> bool:
        """Sets a flag indicating whether the specified user is locked out.

        :param user: The user whose locked out status should be set.
        :return: *True* if the user is locked out, *False* otherwise.
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self._get_user_lockout_store().get_lockout_enabled(user)

    async def get_lockout_end_date(self, user: UserT) -> datetime | None:
        """Gets the last datetime a user's last lockout expired, if any.
        A time value in the past indicates a user is not currently locked out.

        :param user: The user whose lockout date should be retrieved.
        :return: The last datetime a user's lockout expired, if any.
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self._get_user_lockout_store().get_lockout_end_date(user)

    async def set_lockout_end_date(self, user: UserT, lockout_end: datetime) -> IdentityResult:
        """Locks out a user until the specified end date has passed.
        Setting an end date in the past immediately unlocks a user.

        :param user: The user whose lockout date should be set.
        :param lockout_end: The datetime after which the user's lockout should end.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        store = self._get_user_lockout_store()

        if not await store.get_lockout_enabled(user):
            self.logger.warning("Lockout for user failed because lockout is not enabled for this user.")
            return IdentityResult.failed(self.error_describer.UserLockoutNotEnabled())

        await store.set_lockout_end_date(user, normalize_datetime(lockout_end))
        return await self._update_user(user)

    async def access_failed(self, user: UserT) -> IdentityResult:
        """Increments the access failed count for the user.
        If the failed access account is greater than or equal to the configured maximum number of attempts,
        the user will be locked out for the configured lockout time span.

        :param user: The user whose failed access counts to increment.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        store = self._get_user_lockout_store()
        count = await store.increment_access_failed_count(user)

        if count < self.options.lockout.max_failed_access_attempts:
            return await self._update_user(user)

        self.logger.warning("User is locked out.")
        lockout_end = normalize_datetime(datetime.now(timezone.utc) + self.options.lockout.default_lockout_timespan)
        await store.set_lockout_end_date(user, lockout_end)
        await store.reset_access_failed_count(user)
        return await self._update_user(user)

    async def reset_access_failed_count(self, user: UserT) -> IdentityResult:
        """Resets the access failed count for the specified user.

        :param user: The user whose failed access count should be reset.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        store = self._get_user_lockout_store()

        if await store.get_access_failed_count(user) == 0:
            return IdentityResult.success()

        await store.reset_access_failed_count(user)
        return await self._update_user(user)

    async def get_access_failed_count(self, user: UserT) -> int:
        """Retrieves the current number of failed accesses for the given user.

        :param user: The user whose access failed count should be retrieved for.
        :return: The current failed accesses count for the given user.
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self._get_user_lockout_store().get_access_failed_count(user)

    async def get_authentication_token(self, user: UserT, login_provider: str, token_name: str) -> str | None:
        """Returns an authentication token for a user.

        :param user: The user whose authentication token should be retrieved.
        :param login_provider: The authentication scheme for the provider the token is associated with.
        :param token_name: The name of the token.
        :return: The authentication token for the user.
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not login_provider:
            raise ArgumentNoneError("login_provider")
        if not token_name:
            raise ArgumentNoneError("token_name")

        return await self._get_authentication_token_store().get_token(user, login_provider, token_name)

    async def set_authentication_token(
        self,
        user: UserT,
        login_provider: str,
        token_name: str,
        token_value: str | None = None,
    ) -> IdentityResult:
        """Sets an authentication token for a user.

        :param user: The user whose authentication token should be set.
        :param login_provider: The authentication scheme for the provider the token is associated with.
        :param token_name: The name of the token.
        :param token_value: The value of the token.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not login_provider:
            raise ArgumentNoneError("login_provider")
        if not token_name:
            raise ArgumentNoneError("token_name")

        await self._get_authentication_token_store().set_token(user, login_provider, token_name, token_value)
        return await self._update_user(user)

    async def remove_authentication_token(self, user: UserT, login_provider: str, token_name: str) -> IdentityResult:
        """Remove an authentication token for a user.

        :param user: The user whose authentication token should be removed.
        :param login_provider: The authentication scheme for the provider the token is associated with.
        :param token_name: The name of the token.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not login_provider:
            raise ArgumentNoneError("login_provider")
        if not token_name:
            raise ArgumentNoneError("token_name")

        await self._get_authentication_token_store().remove_token(user, login_provider, token_name)
        return await self._update_user(user)

    async def get_authenticator_key(self, user: UserT) -> str | None:
        """Returns the authenticator key for the user.

        :param user: The user.
        :return: The authenticator key for the user.
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self._get_authenticator_key_store().get_authenticator_key(user)

    async def reset_authenticator_key(self, user: UserT) -> IdentityResult:
        """Resets the authenticator key for the user.

        :param user: The user.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        await self._get_authenticator_key_store().set_authenticator_key(user, self.generate_new_authenticator_key())
        await self._update_security_stamp_internal(user)
        return await self._update_user(user)

    @staticmethod
    def generate_new_authenticator_key(length: int = 32) -> str:
        """Generates a value suitable for use in authenticator.

        :param length:
        :return: Returns base32 string.
        """
        return generate_key(length)

    async def generate_new_two_factor_recovery_codes(self, user: UserT, number: int) -> set[str] | None:
        """Generates recovery codes for the user, this invalidates any previous recovery codes for the user.

        :param user: The user to generate recovery codes for.
        :param number: The number of codes to generate.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")

        codes = {self._create_two_factor_recovery_code() for _ in range(number)}
        await self._get_recovery_code_store().replace_codes(user, *codes)
        result = await self._update_user(user)
        if result.succeeded:
            return codes
        return None

    def _create_two_factor_recovery_code(self) -> str:
        """Generate a new recovery code.

        :return: A recovery code.
        """
        return "-".join([self._get_random_recovery_code_chars(), self._get_random_recovery_code_chars()])

    @staticmethod
    def _get_random_recovery_code_chars(number: int = 5) -> str:
        """Returns a random string of length count.

        :param number: The number of characters to generate.
        :return: Returns a random string of length count.
        """
        return "".join(secrets.choice("23456789BCDFGHJKMNPQRTVWXY") for _ in range(number))

    async def redeem_two_factor_recovery_code(self, user: UserT, code: str) -> IdentityResult:
        """Returns whether a recovery code is valid for a user.
        Note: recovery codes are only valid once and will be invalid after use.

        :param user: The user who owns the recovery code.
        :param code: The recovery code to use.
        :return:
        """
        if user is None:
            raise ArgumentNoneError("user")
        if not code:
            raise ArgumentNoneError("code")

        if await self._get_recovery_code_store().redeem_code(user, code):
            return await self._update_user(user)
        return IdentityResult.failed(self.error_describer.RecoveryCodeRedemptionFailed())

    async def count_recovery_codes(self, user: UserT) -> int:
        """Returns how much recovery code is still valid for a user.

        :param user: The user.
        :return: A number of recovery codes still valid.
        """
        if user is None:
            raise ArgumentNoneError("user")

        return await self._get_recovery_code_store().count_codes(user)

    async def get_authenticator_provisioning_uri(
        self,
        user: UserT,
        name: str | None = None,
        title: str = "PyIdentity.Application",
        *,
        digits: int = 6,
        digest: Any = None,
        interval: int = 30,
        image: str | None = None,
    ) -> str:
        """Returns the provisioning URI for the OTP. This can then be encoded in a QR Code and
        used to provision an OTP app like Google Authenticator.

        :param user: The user to create the URI for.
        :param name: Name of the account.
        :param title: The name of the OTP issuer; this will be the organization title of the OTP entry in Authenticator.
        :param digits: Number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        :param digest: Digest function to use in the HMAC (expected to be SHA1)
        :param interval: The time interval in seconds for OTP. This defaults to 30.
        :param image: Optional logo image URL.
        :return: A provisioning URI.
        :raise InvalidOperationError: if authenticator key is invalid.
        """
        if user is None:
            raise ArgumentNoneError("user")

        key = await self.get_authenticator_key(user)

        if not key:
            self.logger.error("Unable to load two-factor authentication user. Authenticator key is invalid.")
            raise InvalidOperationError("Unable to load two-factor authentication user. Authenticator key is invalid.")

        name = name or (self.supports_user_email and await self.get_email(user)) or await self.get_username(user)

        if not name:
            self.logger.error("The name is invalid.")
            raise InvalidOperationError("The name is invalid.")

        return get_provisioning_uri(
            secret=key,
            name=name,
            issuer_name=title,
            digits=digits,
            digest=digest,
            interval=interval,
            image=image,
        )

    async def get_personal_data(self, user: UserT) -> dict[str, Any] | None:
        """Returns the personal data for the user.

        :param user: The user.
        :return: A personal data for the user, if supports.
        """
        if self.supports_user_personal_data:
            return await self._get_user_personal_data_store().get_personal_data(user)
        return None

    def _normalize_name(self, name: str | None) -> str | None:
        """Normalize user or role name for consistent comparisons.

        :param name: The name to normalize.
        :return: Returns the normalized name or None.
        """
        return self.key_normalizer.normalize_name(name) if self.key_normalizer else name

    def _normalize_email(self, email: str | None) -> str | None:
        """Normalize email for consistent comparisons.

        :param email: The email to normalize.
        :return: Returns the normalized email or None.
        """
        return self.key_normalizer.normalize_email(email) if self.key_normalizer else email

    async def _update_password_hash(
        self,
        password_store: IUserPasswordStore[UserT],
        user: UserT,
        new_password: str | None,
        *,
        validate_password: bool = True,
    ) -> IdentityResult:
        """Updates a user's password hash.

        :param password_store: The password store to use.
        :param user: The user to update.
        :param new_password: The new password.
        :param validate_password: Whether to validate the password.
        :return: Whether the password has was successfully updated.
        """
        if validate_password:
            if not new_password:
                raise ArgumentNoneError("new_password")

            validation_result = await self._validate_password(user, new_password)
            if not validation_result.succeeded:
                return validation_result

        hash_ = None
        if not is_none_or_whitespace(new_password):
            hash_ = self.password_hasher.hash_password(user, cast(str, new_password))

        await password_store.set_password_hash(user, hash_)
        await self._update_security_stamp_internal(user)
        return IdentityResult.success()

    async def _validate_user(self, user: UserT) -> IdentityResult:
        """Should return *IdentityResult.success* if validation is successful.
        This is called before saving the user via create or update.
        """
        if user.security_stamp:
            raise InvalidOperationError(Resources.NullSecurityStamp)

        if self.user_validators:
            errors: list[IdentityError] = []

            for validator in self.user_validators:
                result = await validator.validate(self, user)
                if not result.succeeded:
                    errors.extend(result.errors)

            if errors:
                self.logger.warning("User validation failed: %s.", ", ".join(e.code for e in errors))
                return IdentityResult.failed(*errors)

        return IdentityResult.success()

    async def _validate_password(self, user: UserT, password: str) -> IdentityResult:
        """Should return *IdentityResult.success* if validation is successful.
        This is called before updating the password hash.

        :param user: The user.
        :param password: The password.
        :return:
        """
        if self.password_validators:
            errors: list[IdentityError] = []

            for validator in self.password_validators:
                result = await validator.validate(self, password)
                if not result.succeeded:
                    errors.extend(result.errors)

            if errors:
                self.logger.warning("User password validation failed: %s.", ", ".join(e.code for e in errors))
                return IdentityResult.failed(*errors)

        return IdentityResult.success()

    async def create_security_token(self, user: UserT) -> bytes:
        """Creates bytes to use as a security token from the user's security stamp.

        :param user: The user to create security token for.
        :return: The security token bytes.
        """
        if stamp := await self.get_security_stamp(user):
            return ensure_bytes(stamp)
        raise ArgumentNoneError("security_stamp")

    async def _update_security_stamp_internal(self, user: UserT) -> None:
        """Updates the security stamp, if the store supports it.

        :param user: The user to update.
        :return:
        """
        if self.supports_user_security_stamp:
            await self._get_security_store().set_security_stamp(user, uuid7str())

    async def _update_user(self, user: UserT) -> IdentityResult:
        """Called to update the user after validating and updating the normalized email or username.

        :param user: The user to update.
        :return:
        """
        result = await self._validate_user(user)
        if not result.succeeded:
            return result

        await self.update_normalized_username(user)
        await self.update_normalized_email(user)
        return await self.store.update(user)

    def _get_authentication_token_store(self) -> IUserAuthenticationTokenStore[UserT]:
        if self.supports_user_authentication_tokens:
            return cast(IUserAuthenticationTokenStore[UserT], self.store)
        raise NotSupportedError(Resources.StoreNotIUserAuthenticationTokenStore)

    def _get_authenticator_key_store(self) -> IUserAuthenticatorKeyStore[UserT]:
        if self.supports_user_authenticator_key:
            return cast(IUserAuthenticatorKeyStore[UserT], self.store)
        raise NotSupportedError(Resources.StoreNotIUserAuthenticatorKeyStore)

    def _get_recovery_code_store(self) -> IUserTwoFactorRecoveryCodeStore[UserT]:
        if self.supports_user_two_factor_recovery_codes:
            return cast(IUserTwoFactorRecoveryCodeStore[UserT], self.store)
        raise NotSupportedError(Resources.StoreNotIUserTwoFactorRecoveryCodeStore)

    def _get_two_factor_store(self) -> IUserTwoFactorStore[UserT]:
        if self.supports_user_two_factor:
            return cast(IUserTwoFactorStore[UserT], self.store)
        raise NotSupportedError(Resources.StoreNotIUserTwoFactorStore)

    def _get_password_store(self) -> IUserPasswordStore[UserT]:
        if self.supports_user_password:
            return cast(IUserPasswordStore[UserT], self.store)
        raise NotSupportedError(Resources.StoreNotIUserPasswordStore)

    def _get_security_store(self) -> IUserSecurityStampStore[UserT]:
        if self.supports_user_security_stamp:
            return cast(IUserSecurityStampStore[UserT], self.store)
        raise NotSupportedError(Resources.StoreNotIUserSecurityStampStore)

    def _get_user_role_store(self) -> IUserRoleStore[UserT]:
        if self.supports_user_role:
            return cast(IUserRoleStore[UserT], self.store)
        raise NotSupportedError(Resources.StoreNotIUserRoleStore)

    def _get_login_store(self) -> IUserLoginStore[UserT]:
        if self.supports_user_login:
            return cast(IUserLoginStore[UserT], self.store)
        raise NotSupportedError(Resources.StoreNotIUserLoginStore)

    def _get_email_store(self) -> IUserEmailStore[UserT]:
        if self.supports_user_email:
            return cast(IUserEmailStore[UserT], self.store)
        raise NotSupportedError(Resources.StoreNotIUserEmailStore)

    def _get_phone_number_store(self) -> IUserPhoneNumberStore[UserT]:
        if self.supports_user_phone_number:
            return cast(IUserPhoneNumberStore[UserT], self.store)
        raise NotSupportedError(Resources.StoreNotIUserPhoneNumberStore)

    def _get_claim_store(self) -> IUserClaimStore[UserT]:
        if self.supports_user_claim:
            return cast(IUserClaimStore[UserT], self.store)
        raise NotSupportedError(Resources.StoreNotIUserClaimStore)

    def _get_user_lockout_store(self) -> IUserLockoutStore[UserT]:
        if self.supports_user_lockout:
            return cast(IUserLockoutStore[UserT], self.store)
        raise NotSupportedError(Resources.StoreNotIUserLockoutStore)

    def _get_user_personal_data_store(self) -> IUserPersonalDataStore[UserT]:
        if self.supports_user_personal_data:
            return cast(IUserPersonalDataStore[UserT], self.store)
        raise NotSupportedError(Resources.StoreNotIUserPersonalDataStore)
