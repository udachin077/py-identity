from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Generic

from pydentity.models import RoleT, UserT

if TYPE_CHECKING:
    from datetime import datetime

    from pydentity.identity_result import IdentityResult
    from pydentity.security.claims import Claim
    from pydentity.user_login_info import UserLoginInfo

__all__ = [
    "IRoleClaimStore",
    "IRoleStore",
    "IUserAuthenticationTokenStore",
    "IUserAuthenticatorKeyStore",
    "IUserClaimStore",
    "IUserEmailStore",
    "IUserLockoutStore",
    "IUserLoginStore",
    "IUserPasswordStore",
    "IUserPersonalDataStore",
    "IUserPhoneNumberStore",
    "IUserRoleStore",
    "IUserSecurityStampStore",
    "IUserStore",
    "IUserTwoFactorRecoveryCodeStore",
    "IUserTwoFactorStore",
]


class IRoleStore(Generic[RoleT], ABC):
    """Provides an abstraction for the storage and management of roles."""

    @abstractmethod
    def create_model_from_dict(self, **kwargs: Any) -> RoleT:
        """Create user model from kwargs.

        :param kwargs: The kwargs passed to the model.
        :return:
        """

    @abstractmethod
    async def all(self) -> list[RoleT]:
        """Returns all roles."""

    @abstractmethod
    async def create(self, role: RoleT) -> IdentityResult:
        """Create a new role in a store.

        :param role: The role to create in the store.
        :return:
        """

    @abstractmethod
    async def update(self, role: RoleT) -> IdentityResult:
        """Updates a role from the store.

        :param role: The role to update in the store.
        :return:
        """

    @abstractmethod
    async def delete(self, role: RoleT) -> IdentityResult:
        """Deletes a role from the store.

        :param role: The role to delete from the store.
        :return:
        """

    @abstractmethod
    async def find_by_id(self, role_id: str) -> RoleT | None:
        """Finds the role who has the specified ID.

        :param role_id: The role ID to look for.
        :return:
        """

    @abstractmethod
    async def find_by_name(self, normalized_name: str) -> RoleT | None:
        """Finds the role who has the specified normalized name.

        :param normalized_name: The normalized role name to look for.
        :return:
        """

    @abstractmethod
    async def get_role_id(self, role: RoleT) -> str:
        """Gets the ID for a role from the store.

        :param role: The role whose ID should be returned.
        :return:
        """

    @abstractmethod
    async def get_role_name(self, role: RoleT) -> str | None:
        """Gets the name of a role from the store.

        :param role: The role whose name should be returned.
        :return:
        """

    @abstractmethod
    async def set_role_name(self, role: RoleT, role_name: str | None) -> None:
        """Sets the name of a role in the store.

        :param role: The role whose name should be set.
        :param role_name: The name of the role.
        :return:
        """

    @abstractmethod
    async def get_normalized_role_name(self, role: RoleT) -> str | None:
        """Get a role's normalized name.

        :param role: The role whose normalized name should be retrieved.
        :return:
        """

    @abstractmethod
    async def set_normalized_role_name(self, role: RoleT, normalized_name: str | None) -> None:
        """Set a role's normalized name.

        :param role: The role whose normalized name.
        :param normalized_name: The normalized name to set.
        :return:
        """


class IRoleClaimStore(IRoleStore[RoleT], Generic[RoleT], ABC):
    @abstractmethod
    async def get_claims(self, role: RoleT) -> list[Claim]:
        """Get the claims associated with the specified role."""

    @abstractmethod
    async def add_claim(self, role: RoleT, claims: Claim) -> None:
        """Add a new claim to a role."""

    @abstractmethod
    async def remove_claim(self, role: RoleT, claim: Claim) -> None:
        """Remove a claim from a role."""


class IUserStore(Generic[UserT], ABC):
    """Provides an abstraction for a store which manages user accounts."""

    @abstractmethod
    def create_model_from_dict(self, **kwargs: Any) -> UserT:
        """Create model from kwargs.

        :param kwargs: The kwargs passed to the model.
        :return: Returns user.
        """

    @abstractmethod
    async def all(self) -> list[UserT]:
        """Returns all auth.

        :return:
        """

    @abstractmethod
    async def create(self, user: UserT) -> IdentityResult:
        """Creates the specified user in the user store.

        :param user: The user to create.
        :return:
        """

    @abstractmethod
    async def update(self, user: UserT) -> IdentityResult:
        """Updates the specified user in the user store.

        :param user: The user to update.
        :return:
        """

    @abstractmethod
    async def delete(self, user: UserT) -> IdentityResult:
        """Deletes the specified user from the user store.

        :param user: The user to delete.
        :return:
        """

    @abstractmethod
    async def find_by_id(self, user_id: str) -> UserT | None:
        """Finds and returns a user, if any, who has the specified user_id.

        :param user_id: The user ID to search for.
        :return:
        """

    @abstractmethod
    async def find_by_name(self, normalized_username: str) -> UserT | None:
        """Finds and returns a user, if any, who has the specified normalized username.

        :param normalized_username: The normalized username to search for.
        :return:
        """

    @abstractmethod
    async def get_user_id(self, user: UserT) -> str:
        """Gets the user identifier for the specified user.

        :param user: The user whose identifier should be retrieved.
        :return:
        """

    @abstractmethod
    async def get_username(self, user: UserT) -> str | None:
        """Gets the username for the specified user.

        :param user: The user whose name should be retrieved.
        :return:
        """

    @abstractmethod
    async def set_username(self, user: UserT, username: str | None) -> None:
        """Sets the given username for the specified user.

        :param user: The user whose name should be set.
        :param username: The username to set.
        :return:
        """

    @abstractmethod
    async def get_normalized_username(self, user: UserT) -> str | None:
        """Gets the normalized username for the specified user.

        :param user: The user whose normalized name should be retrieved.
        :return:
        """

    @abstractmethod
    async def set_normalized_username(self, user: UserT, normalized_name: str | None) -> None:
        """Sets the given normalized name for the specified user.

        :param user: The user whose name should be set.
        :param normalized_name: The normalized name to set.
        :return:
        """


class IUserAuthenticationTokenStore(IUserStore[UserT], Generic[UserT], ABC):
    """Provides an abstraction to store a user's authentication tokens."""

    @abstractmethod
    async def get_token(self, user: UserT, login_provider: str, name: str) -> str | None:
        """Returns the token value.

        :param user: The user.
        :param login_provider: The authentication provider for the token.
        :param name: The name of the token.
        :return:
        """

    @abstractmethod
    async def remove_token(self, user: UserT, login_provider: str, name: str) -> None:
        """Deletes a token for a user.

        :param user: The user.
        :param login_provider: The authentication provider for the token.
        :param name: The name of the token.
        :return:
        """

    @abstractmethod
    async def set_token(self, user: UserT, login_provider: str, name: str, value: str | None) -> None:
        """Sets the token value for a particular user.

        :param user: The user.
        :param login_provider: The authentication provider for the token.
        :param name: The name of the token.
        :param value:
        :return:
        """


class IUserAuthenticatorKeyStore(IUserStore[UserT], Generic[UserT], ABC):
    """Provides an abstraction for a store which stores info about user's authenticator."""

    @abstractmethod
    async def get_authenticator_key(self, user: UserT) -> str | None:
        """Get the authenticator key for the user.

        :param user: The user whose security stamp should be set.
        :return:
        """

    @abstractmethod
    async def set_authenticator_key(self, user: UserT, key: str) -> None:
        """Sets the authenticator key for the specified user.

        :param user: The user whose authenticator key should be set.
        :param key: The authenticator key to set.
        :return:
        """


class IUserClaimStore(IUserStore[UserT], Generic[UserT], ABC):
    """Provides an abstraction for a store of claims for a user."""

    @abstractmethod
    async def add_claims(self, user: UserT, *claims: Claim) -> None:
        """Add claims to a user.

        :param user: The user to add the claim to.
        :param claims: The collection of Claims to add.
        :return:
        """

    @abstractmethod
    async def get_claims(self, user: UserT) -> list[Claim]:
        """Gets a list of Claim`s to be belonging to the specified user.

        :param user: The user whose claims to retrieve.
        :return:
        """

    @abstractmethod
    async def get_users_for_claim(self, claim: Claim) -> list[UserT]:
        """:param claim:
        :return:
        """

    @abstractmethod
    async def remove_claims(self, user: UserT, *claims: Claim) -> None:
        """Removes the specified claims from the given user.

        :param user: The user to remove the specified claims from.
        :param claims: A collection of Claims to be removed.
        :return:
        """

    @abstractmethod
    async def replace_claim(self, user: UserT, claim: Claim, new_claim: Claim) -> None:
        """Replaces the given claim on the specified user with the new_claim.

        :param user: The user to replace the claim on.
        :param claim: The claim to replace.
        :param new_claim: The new claim to replace the existing claim with.
        :return:
        """


class IUserEmailStore(IUserStore[UserT], Generic[UserT], ABC):
    """Provides an abstraction for the storage and management of user email addresses."""

    @abstractmethod
    async def find_by_email(self, normalized_email: str) -> UserT | None:
        """Gets the user, if any, associated with the specified, normalized email address.

        :param normalized_email: The normalized email address to return the user for.
        :return:
        """

    @abstractmethod
    async def get_email(self, user: UserT) -> str | None:
        """Gets the email address for the specified user.

        :param user: The user whose email should be returned.
        :return:
        """

    @abstractmethod
    async def set_email(self, user: UserT, email: str | None) -> None:
        """Sets the email address for a user.

        :param user: The user whose email should be set.
        :param email: The email to set.
        :return:
        """

    @abstractmethod
    async def get_email_confirmed(self, user: UserT) -> bool:
        """Gets a flag indicating whether the email address for the specified user has been verified,
        True if the email address is verified otherwise False.

        :param user: The user whose email confirmation status should be returned.
        :return:
        """

    @abstractmethod
    async def get_normalized_email(self, user: UserT) -> str | None:
        """Returns the normalized email for the specified user.

        :param user: The user whose email address to retrieve.
        :return:
        """

    @abstractmethod
    async def set_normalized_email(self, user: UserT, normalized_email: str | None) -> None:
        """Sets the normalized email for the specified user.

        :param user: The user whose email address to set.
        :param normalized_email: The normalized email to set for the specified user.
        :return:
        """

    @abstractmethod
    async def set_email_confirmed(self, user: UserT, confirmed: bool) -> None:
        """Sets the flag indicating whether the specified user's email address has been confirmed or not.

        :param user: The user whose email confirmation status should be set.
        :param confirmed: A flag indicating if the email address has been confirmed,
        True if the address is confirmed otherwise False.
        :return:
        """


class IUserLockoutStore(IUserStore[UserT], Generic[UserT], ABC):
    """Provides an abstraction for a storing information which can be used to implement account lockout,
    including access failures and lockout status.
    """

    @abstractmethod
    async def get_access_failed_count(self, user: UserT) -> int:
        """Retrieves the current failed access count for the specified user.

        :param user: The user whose failed access count should be retrieved.
        :return:
        """

    @abstractmethod
    async def get_lockout_enabled(self, user: UserT) -> bool:
        """Retrieves a flag indicating whether user lockout can be enabled for the specified user.

        :param user: The user whose ability to be locked out should be returned.
        :return:
        """

    @abstractmethod
    async def get_lockout_end_date(self, user: UserT) -> datetime | None:
        """Gets the last datetime a user's last lockout expired, if any.
        Any time in the past should be indicated a user is not locked out.

        :param user: The user whose lockout date should be retrieved.
        :return:
        """

    @abstractmethod
    async def increment_access_failed_count(self, user: UserT) -> int:
        """Records that failed access has occurred, incrementing the failed access count.

        :param user: The user whose cancellation count should be incremented.
        :return:
        """

    @abstractmethod
    async def reset_access_failed_count(self, user: UserT) -> None:
        """Resets a user's failed access count.

        :param user: The user whose failed access count should be reset.
        :return:
        """

    @abstractmethod
    async def set_lockout_enabled(self, user: UserT, enabled: bool) -> None:
        """Set the flag indicating if the specified user can be locked out.

        :param user: The user whose ability to be locked out should be set.
        :param enabled: A flag indicating if lock out can be enabled for the specified user.
        :return:
        """

    @abstractmethod
    async def set_lockout_end_date(self, user: UserT, lockout_end: datetime) -> None:
        """Locks out a user until the specified end date has passed.
        Setting an end date in the past immediately unlocks a user.

        :param user: The user whose lockout date should be set.
        :param lockout_end: The datetime after which the user's lockout should end.
        :return:
        """


class IUserLoginStore(IUserStore[UserT], Generic[UserT], ABC):
    """Provides an abstraction for storing information that maps external login information provided
    by Microsoft Account, Facebook, etc. to a user account.
    """

    @abstractmethod
    async def add_login(self, user: UserT, login: UserLoginInfo) -> None:
        """Add an external UserLoginInfo to the specified user.

        :param user: The user to add the login to.
        :param login: The external UserLoginInfo to add to the specified user.
        :return:
        """

    @abstractmethod
    async def find_by_login(self, login_provider: str, provider_key: str) -> UserT | None:
        """Retrieves the user associated with the specified login provider and login provider key.

        :param login_provider: The login provider who provided the provider_key.
        :param provider_key: The key provided by the login_provider to identify a user.
        :return:
        """

    @abstractmethod
    async def get_logins(self, user: UserT) -> list[UserLoginInfo]:
        """Retrieves the associated logins for the specified user.

        :param user: The user whose associated logins to retrieve.
        :return:
        """

    @abstractmethod
    async def remove_login(self, user: UserT, login_provider: str, provider_key: str) -> None:
        """Attempts to remove the provided login information from the specified user
        and returns a flag indicating whether the removal succeeds or not.

        :param user: The user to remove the login information from.
        :param login_provider: The login provides that information should be removed.
        :param provider_key: The key given by the external login provider for the specified user.
        :return:
        """


class IUserPasswordStore(IUserStore[UserT], Generic[UserT], ABC):
    """Provides an abstraction for a store containing auth password hashes."""

    @abstractmethod
    async def get_password_hash(self, user: UserT) -> str | None:
        """Gets the password hash for the specified user.

        :param user: The user whose password hash to retrieve.
        :return:
        """

    @abstractmethod
    async def has_password(self, user: UserT) -> bool:
        """Gets a flag indicating whether the specified user has a password.

        :param user: The user to return a flag for, indicating whether they have a password or not.
        :return:
        """

    @abstractmethod
    async def set_password_hash(self, user: UserT, password_hash: str | None) -> None:
        """Sets the password hash for the specified user.

        :param user: The user whose password hash is to set.
        :param password_hash: The password hash to set.
        :return:
        """


class IUserPhoneNumberStore(IUserStore[UserT], Generic[UserT], ABC):
    """Provides an abstraction for a store containing auth telephone numbers."""

    @abstractmethod
    async def get_phone_number(self, user: UserT) -> str | None:
        """Gets the telephone number, if any, for the specified user.

        :param user: The user whose telephone number should be retrieved.
        :return:
        """

    @abstractmethod
    async def set_phone_number(self, user: UserT, phone_number: str | None) -> None:
        """Sets the telephone number for the specified user.

        :param user: The user whose telephone number should be set.
        :param phone_number: The telephone number to set.
        :return:
        """

    @abstractmethod
    async def get_phone_number_confirmed(self, user: UserT) -> bool:
        """Gets a flag indicating whether the specified user's telephone number has been confirmed.

        :param user: The user to return a flag for, indicating whether their telephone number is confirmed.
        :return:
        """

    @abstractmethod
    async def set_phone_number_confirmed(self, user: UserT, confirmed: bool) -> None:
        """Sets a flag indicating if the specified user's phone number has been confirmed.

        :param user: The user whose telephone number confirmation status should be set.
        :param confirmed: A flag indicating whether the user's telephone number has been confirmed.
        :return:
        """


class IUserRoleStore(IUserStore[UserT], Generic[UserT], ABC):
    """Provides an abstraction for a store which maps auth to roles."""

    @abstractmethod
    async def add_to_role(self, user: UserT, normalized_role_name: str) -> None:
        """Add the specified user to the named role.

        :param user: The user to add to the named role.
        :param normalized_role_name: The name of the role to add the user to.
        :return:
        """

    @abstractmethod
    async def get_roles(self, user: UserT) -> list[str]:
        """Gets a list of role names the specified user belongs to.

        :param user: The user whose role names to retrieve.
        :return:
        """

    @abstractmethod
    async def get_users_in_role(self, normalized_role_name: str) -> list[UserT]:
        """Returns a list of Users who are members of the named role.

        :param normalized_role_name: The name of the role whose membership should be returned.
        :return:
        """

    @abstractmethod
    async def is_in_role(self, user: UserT, normalized_role_name: str) -> bool:
        """Returns a flag indicating whether the specified user is a member of the given named role.

        :param user: The user whose role membership should be checked.
        :param normalized_role_name: The name of the role to be checked.
        :return:
        """

    @abstractmethod
    async def remove_from_role(self, user: UserT, normalized_role_name: str) -> None:
        """Remove the specified user from the named role.

        :param user: The user to remove the named role from.
        :param normalized_role_name: The name of the role to remove.
        :return:
        """


class IUserSecurityStampStore(IUserStore[UserT], Generic[UserT], ABC):
    """Provides an abstraction for a store which stores a user's security stamp."""

    @abstractmethod
    async def get_security_stamp(self, user: UserT) -> str | None:
        """Get the security stamp for the specified user.

        :param user: The user whose security stamp should be set.
        :return:
        """

    @abstractmethod
    async def set_security_stamp(self, user: UserT, stamp: str) -> None:
        """Sets the provided security stamp for the specified user.

        :param user: The user whose security stamp should be set.
        :param stamp: The security stamp to set.
        :return:
        """


class IUserTwoFactorRecoveryCodeStore(IUserStore[UserT], Generic[UserT], ABC):
    """Provides an abstraction for a store which stores a user's recovery codes."""

    @abstractmethod
    async def count_codes(self, user: UserT) -> int:
        """Returns how much recovery code is still valid for a user.

        :param user: The user who owns the recovery code.
        :return:
        """

    @abstractmethod
    async def redeem_code(self, user: UserT, code: str) -> bool:
        """Returns whether a recovery code is valid for a user.
        Note: recovery codes are only valid once and will be invalid after use.

        :param user: The user who owns the recovery code.
        :param code: The recovery code to use.
        :return:
        """

    @abstractmethod
    async def replace_codes(self, user: UserT, *recovery_codes: str) -> None:
        """Updates the recovery codes for the user while invalidating any previous recovery codes.

        :param user: The user to store new recovery codes for.
        :param recovery_codes: The new recovery codes for the user.
        :return:
        """


class IUserTwoFactorStore(IUserStore[UserT], Generic[UserT], ABC):
    """Provides an abstraction to store a flag indicating whether a user has two-factor authentication enabled."""

    @abstractmethod
    async def get_two_factor_enabled(self, user: UserT) -> bool:
        """Returns a flag indicating whether the specified user has two-factor authentication enabled or not.

        :param user: The user whose two-factor authentication enabled status should be set.
        :return:
        """

    @abstractmethod
    async def set_two_factor_enabled(self, user: UserT, enabled: bool) -> None:
        """Sets a flag indicating whether the specified user has two-factor authentication enabled or not.

        :param user: The user whose two-factor authentication enabled status should be set.
        :param enabled: A flag indicating whether the specified user has two-factor authentication enabled.
        :return:
        """


class IUserPersonalDataStore(IUserStore[UserT], Generic[UserT], ABC):
    @abstractmethod
    async def get_personal_data(self, user: UserT) -> dict[str, Any] | None:
        """Returns the personal data for the specified user.

        :param user: The user whose personal data should be retrieved.
        :return:
        """
