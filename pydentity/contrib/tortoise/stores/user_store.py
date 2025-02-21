from datetime import datetime, timezone
from typing import Any, Final, Generic
from uuid import uuid4

from tortoise import BaseDBAsyncClient

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
from pydentity.exc import ArgumentNoneError, InvalidOperationError, PersonalDataError
from pydentity.identity_error_describer import IdentityErrorDescriber
from pydentity.identity_result import IdentityResult
from pydentity.models import RoleT, UserClaimT, UserLoginT, UserRoleT, UserT, UserTokenT
from pydentity.resources import Resources
from pydentity.security.claims import Claim
from pydentity.user_login_info import UserLoginInfo

__all__ = ["UserStore"]


class UserStore(
    IUserAuthenticationTokenStore[UserT],
    IUserAuthenticatorKeyStore[UserT],
    IUserClaimStore[UserT],
    IUserEmailStore[UserT],
    IUserLockoutStore[UserT],
    IUserLoginStore[UserT],
    IUserPasswordStore[UserT],
    IUserPersonalDataStore[UserT],
    IUserPhoneNumberStore[UserT],
    IUserRoleStore[UserT],
    IUserSecurityStampStore[UserT],
    IUserTwoFactorRecoveryCodeStore[UserT],
    IUserTwoFactorStore[UserT],
    IUserStore[UserT],
    Generic[UserT],
):
    users: type[UserT]
    roles: type[RoleT]
    user_roles: type[UserRoleT]
    user_claims: type[UserClaimT]
    user_logins: type[UserLoginT]
    user_tokens: type[UserTokenT]

    INTERNAL_LOGIN_PROVIDER: Final[str] = "[PyIdentity:UserStore]"
    AUTHENTICATOR_KEY_TOKEN_NAME: Final[str] = "[PyIdentity:AuthenticatorKey]"
    RECOVERY_CODE_TOKEN_NAME: Final[str] = "[PyIdentity:RecoveryCodes]"

    def __init__(
        self, using_db: BaseDBAsyncClient | None = None, error_describer: IdentityErrorDescriber | None = None
    ) -> None:
        self.using_db = using_db
        self.error_describer = error_describer or IdentityErrorDescriber()

    def create_model_from_dict(self, **kwargs) -> UserT:
        return self.users(**kwargs)

    async def refresh(self, user: UserT) -> None:
        if user is None:
            raise ArgumentNoneError("user")

        await user.refresh_from_db(using_db=self.using_db)

    async def all(self) -> list[UserT]:
        return await self.users.all(using_db=self.using_db)

    async def create(self, user: UserT) -> IdentityResult:
        if user is None:
            raise ArgumentNoneError("user")

        await user.save(using_db=self.using_db)
        await self.refresh(user)
        return IdentityResult.success()

    async def update(self, user: UserT) -> IdentityResult:
        if user is None:
            raise ArgumentNoneError("user")

        if not await self.users.filter(id=user.id, concurrency_stamp=user.concurrency_stamp).exists():
            return IdentityResult.failed(self.error_describer.ConcurrencyFailure())

        user.concurrency_stamp = str(uuid4())
        await user.save(using_db=self.using_db)
        await self.refresh(user)
        return IdentityResult.success()

    async def delete(self, user: UserT) -> IdentityResult:
        if user is None:
            raise ArgumentNoneError("user")

        await user.delete(using_db=self.using_db)
        return IdentityResult.success()

    async def find_by_id(self, user_id: str) -> UserT | None:
        if user_id is None:
            raise ArgumentNoneError("user_id")

        return await self.users.get_or_none(id=user_id, using_db=self.using_db)

    async def find_by_name(self, normalized_username: str) -> UserT | None:
        if normalized_username is None:
            raise ArgumentNoneError("normalized_username")

        return await self.users.get_or_none(normalized_username=normalized_username, using_db=self.using_db)

    async def get_user_id(self, user: UserT) -> str:
        if user is None:
            raise ArgumentNoneError("user")

        return user.id

    async def get_username(self, user: UserT) -> str | None:
        if user is None:
            raise ArgumentNoneError("user")

        return user.username

    async def set_username(self, user: UserT, username: str | None) -> None:
        if user is None:
            raise ArgumentNoneError("user")

        user.username = username

    async def get_normalized_username(self, user: UserT) -> str | None:
        if user is None:
            raise ArgumentNoneError("user")

        return user.normalized_username

    async def set_normalized_username(self, user: UserT, normalized_name: str | None) -> None:
        if user is None:
            raise ArgumentNoneError("user")

        user.normalized_username = normalized_name

    async def find_by_email(self, normalized_email: str) -> UserT | None:
        if normalized_email is None:
            raise ArgumentNoneError("normalized_email")

        return await self.users.get_or_none(normalized_email=normalized_email, using_db=self.using_db)

    async def get_email(self, user: UserT) -> str | None:
        if user is None:
            raise ArgumentNoneError("user")

        return user.email

    async def set_email(self, user: UserT, email: str | None) -> None:
        if user is None:
            raise ArgumentNoneError("user")

        user.email = email

    async def get_email_confirmed(self, user: UserT) -> bool:
        if user is None:
            raise ArgumentNoneError("user")

        return bool(user.email and user.email_confirmed)

    async def get_normalized_email(self, user: UserT) -> str | None:
        if user is None:
            raise ArgumentNoneError("user")

        return user.normalized_email

    async def set_normalized_email(self, user: UserT, normalized_email: str | None) -> None:
        if user is None:
            raise ArgumentNoneError("user")

        user.normalized_email = normalized_email

    async def set_email_confirmed(self, user: UserT, confirmed: bool) -> None:
        if user is None:
            raise ArgumentNoneError("user")

        user.email_confirmed = confirmed

    async def get_password_hash(self, user: UserT) -> str | None:
        if user is None:
            raise ArgumentNoneError("user")

        return user.password_hash

    async def has_password(self, user: UserT) -> bool:
        if user is None:
            raise ArgumentNoneError("user")

        return bool(user.password_hash)

    async def set_password_hash(self, user: UserT, password_hash: str | None) -> None:
        if user is None:
            raise ArgumentNoneError("user")

        user.password_hash = password_hash

    async def get_phone_number(self, user: UserT) -> str | None:
        if user is None:
            raise ArgumentNoneError("user")

        return user.phone_number

    async def set_phone_number(self, user: UserT, phone_number: str | None) -> None:
        if user is None:
            raise ArgumentNoneError("user")

        user.phone_number = phone_number

    async def get_phone_number_confirmed(self, user: UserT) -> bool:
        if user is None:
            raise ArgumentNoneError("user")

        return bool(user.phone_number and user.phone_number_confirmed)

    async def set_phone_number_confirmed(self, user: UserT, confirmed: bool) -> None:
        if user is None:
            raise ArgumentNoneError("user")

        user.phone_number_confirmed = confirmed

    async def get_access_failed_count(self, user: UserT) -> int:
        if user is None:
            raise ArgumentNoneError("user")

        return user.access_failed_count

    async def get_lockout_enabled(self, user: UserT) -> bool:
        if user is None:
            raise ArgumentNoneError("user")

        return user.lockout_enabled

    async def get_lockout_end_date(self, user: UserT) -> datetime | None:
        if user is None:
            raise ArgumentNoneError("user")

        lockout_end = user.lockout_end
        return lockout_end.astimezone(timezone.utc) if lockout_end else None

    async def increment_access_failed_count(self, user: UserT) -> int:
        if user is None:
            raise ArgumentNoneError("user")

        user.access_failed_count += 1
        return user.access_failed_count + 1

    async def reset_access_failed_count(self, user: UserT) -> None:
        if user is None:
            raise ArgumentNoneError("user")

        user.access_failed_count = 0

    async def set_lockout_enabled(self, user: UserT, enabled: bool) -> None:
        if user is None:
            raise ArgumentNoneError("user")

        user.lockout_enabled = enabled

    async def set_lockout_end_date(self, user: UserT, lockout_end: datetime | None) -> None:
        if user is None:
            raise ArgumentNoneError("user")

        user.lockout_end = lockout_end

    async def get_security_stamp(self, user: UserT) -> str | None:
        if user is None:
            raise ArgumentNoneError("user")

        return user.security_stamp

    async def set_security_stamp(self, user: UserT, stamp: str) -> None:
        if user is None:
            raise ArgumentNoneError("user")

        user.security_stamp = stamp

    async def add_to_role(self, user: UserT, normalized_role_name: str) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if normalized_role_name is None:
            raise ArgumentNoneError("normalized_role_name")

        if role := await self._find_role(normalized_role_name):
            await self.user_roles(user_id=user.id, role_id=role.id).save(using_db=self.using_db)
            return

        raise InvalidOperationError(Resources.RoleNotFound.format(normalized_role_name))

    async def get_roles(self, user: UserT) -> list[str]:
        if user is None:
            raise ArgumentNoneError("user")

        return await self.roles.filter(users__id=user.id).using_db(self.using_db).values_list("name", flat=True)

    async def get_users_in_role(self, normalized_role_name: str) -> list[UserT]:
        if normalized_role_name is None:
            raise ArgumentNoneError("normalized_role_name")

        if role := await self.roles.get_or_none(normalized_name=normalized_role_name, using_db=self.using_db):
            return await role.users.all().using_db(self.using_db)

        raise InvalidOperationError(Resources.RoleNotFound.format(normalized_role_name))

    async def is_in_role(self, user: UserT, normalized_role_name: str) -> bool:
        if user is None:
            raise ArgumentNoneError("user")
        if normalized_role_name is None:
            raise ArgumentNoneError("normalized_role_name")

        return await self.user_roles.exists(
            user_id=user.id,
            role__normalized_name=normalized_role_name,
            using_db=self.using_db,
        )

    async def remove_from_role(self, user: UserT, normalized_role_name: str) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if normalized_role_name is None:
            raise ArgumentNoneError("normalized_role_name")

        if role := await self.roles.get_or_none(normalized_name=normalized_role_name, using_db=self.using_db):
            await self.user_roles.filter(user_id=user.id, role_id=role.id).using_db(self.using_db).delete()

    async def add_login(self, user: UserT, login: UserLoginInfo) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if login is None:
            raise ArgumentNoneError("login")

        await self.user_logins.from_user_login_info(user.id, login).save(using_db=self.using_db)

    async def find_by_login(self, login_provider: str, provider_key: str) -> UserT | None:
        if login_provider is None:
            raise ArgumentNoneError("login_provider")
        if provider_key is None:
            raise ArgumentNoneError("provider_key")

        return await self.users.get_or_none(
            logins__login_provider=login_provider,
            logins__provider_key=provider_key,
            using_db=self.using_db,
        )

    async def get_logins(self, user: UserT) -> list[UserLoginInfo]:
        if user is None:
            raise ArgumentNoneError("user")

        user_logins = await self.user_logins.filter(user_id=user.id).using_db(self.using_db)
        return [ul.to_user_login_info() for ul in user_logins]

    async def remove_login(self, user: UserT, login_provider: str, provider_key: str) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if login_provider is None:
            raise ArgumentNoneError("login_provider")
        if provider_key is None:
            raise ArgumentNoneError("provider_key")

        await (
            self.user_logins.filter(
                user_id=user.id,
                login_provider=login_provider,
                provider_key=provider_key,
            )
            .using_db(self.using_db)
            .delete()
        )

    async def get_token(self, user: UserT, login_provider: str, name: str) -> str | None:
        if user is None:
            raise ArgumentNoneError("user")
        if login_provider is None:
            raise ArgumentNoneError("login_provider")
        if name is None:
            raise ArgumentNoneError("name")

        if token := await self._find_token(user, login_provider, name):
            return token.value

        return None

    async def remove_token(self, user: UserT, login_provider: str, name: str) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if login_provider is None:
            raise ArgumentNoneError("login_provider")
        if name is None:
            raise ArgumentNoneError("name")

        await (
            self.user_tokens.filter(user_id=user.id, login_provider=login_provider, name=name)
            .using_db(self.using_db)
            .delete()
        )

    async def set_token(self, user: UserT, login_provider: str, name: str, value: str | None) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if login_provider is None:
            raise ArgumentNoneError("login_provider")
        if name is None:
            raise ArgumentNoneError("name")

        defaults = {
            "user_id": user.id,
            "login_provider": login_provider,
            "name": name,
            "value": value,
        }
        await self.user_tokens.update_or_create(
            defaults=defaults,
            using_db=self.using_db,
            user_id=user.id,
            login_provider=login_provider,
            name=name,
        )

    async def get_two_factor_enabled(self, user: UserT) -> bool:
        if user is None:
            raise ArgumentNoneError("user")

        return user.two_factor_enabled

    async def set_two_factor_enabled(self, user: UserT, enabled: bool) -> None:
        if user is None:
            raise ArgumentNoneError("user")

        user.two_factor_enabled = enabled

    async def get_authenticator_key(self, user: UserT) -> str | None:
        if user is None:
            raise ArgumentNoneError("user")

        return await self.get_token(user, self.INTERNAL_LOGIN_PROVIDER, self.AUTHENTICATOR_KEY_TOKEN_NAME)

    async def set_authenticator_key(self, user: UserT, key: str) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if key is None:
            raise ArgumentNoneError("key")

        return await self.set_token(user, self.INTERNAL_LOGIN_PROVIDER, self.AUTHENTICATOR_KEY_TOKEN_NAME, key)

    async def count_codes(self, user: UserT) -> int:
        if user is None:
            raise ArgumentNoneError("user")

        merged_codes = (await self.get_token(user, self.INTERNAL_LOGIN_PROVIDER, self.RECOVERY_CODE_TOKEN_NAME)) or ""
        if merged_codes:
            return merged_codes.count(";") + 1
        return 0

    async def redeem_code(self, user: UserT, code: str) -> bool:
        if user is None:
            raise ArgumentNoneError("user")
        if code is None:
            raise ArgumentNoneError("code")

        merged_codes = (await self.get_token(user, self.INTERNAL_LOGIN_PROVIDER, self.RECOVERY_CODE_TOKEN_NAME)) or ""
        split_codes = merged_codes.split(";")

        if code in split_codes:
            split_codes.remove(code)
            await self.replace_codes(user, *split_codes)
            return True

        return False

    async def replace_codes(self, user: UserT, *recovery_codes: str) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if not recovery_codes:
            raise ArgumentNoneError("recovery_codes")

        merged_codes = ";".join(recovery_codes)
        return await self.set_token(
            user,
            self.INTERNAL_LOGIN_PROVIDER,
            self.RECOVERY_CODE_TOKEN_NAME,
            merged_codes,
        )

    async def add_claims(self, user: UserT, *claims: Claim) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if not claims:
            raise ArgumentNoneError("claims")

        await self.user_claims.bulk_create(
            [self.user_claims.from_claim(user.id, claim) for claim in claims],
            using_db=self.using_db,
        )

    async def get_claims(self, user: UserT) -> list[Claim]:
        if user is None:
            raise ArgumentNoneError("user")

        user_claims = await self.user_claims.filter(user_id=user.id).using_db(self.using_db)
        return [uc.to_claim() for uc in user_claims]

    async def get_users_for_claim(self, claim: Claim) -> list[UserT]:
        if claim is None:
            raise ArgumentNoneError("claim")

        return await self.users.filter(claims__claim_type=claim.type, claims__claim_value=claim.value).using_db(
            self.using_db
        )

    async def remove_claims(self, user: UserT, *claims: Claim) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if not claims:
            raise ArgumentNoneError("claims")

        for claim in claims:
            await (
                self.user_claims.filter(user_id=user.id, claim_type=claim.type, claim_value=claim.value)
                .using_db(self.using_db)
                .delete()
            )

    async def replace_claim(self, user: UserT, claim: Claim, new_claim: Claim) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if claim is None:
            raise ArgumentNoneError("claim")
        if new_claim is None:
            raise ArgumentNoneError("new_claim")

        defaults = {
            "user_id": user.id,
            "claim_type": new_claim.type,
            "claim_value": new_claim.value,
        }
        await self.user_claims.update_or_create(
            defaults=defaults,
            using_db=self.using_db,
            user_id=user.id,
            claim_type=claim.type,
            claim_value=claim.value,
        )

    async def get_personal_data(self, user: UserT) -> dict[str, Any] | None:
        if user is None:
            raise ArgumentNoneError("user")

        if hasattr(user.Meta, "personal_data"):
            return {p: getattr(user, p) for p in user.Meta.personal_data}

        raise PersonalDataError(
            f"The model '{user.__class__}' does not support receiving personal data.\n"
            f"The 'Meta' must have the 'personal_data' attribute, which lists the fields related to personal data."
        )

    async def _find_token(self, user: UserT, login_provider: str, name: str) -> UserTokenT | None:
        return await self.user_tokens.get_or_none(
            user_id=user.id,
            login_provider=login_provider,
            name=name,
            using_db=self.using_db,
        )

    async def _find_role(self, name: str) -> RoleT | None:
        return await self.roles.get_or_none(normalized_name=name, using_db=self.using_db)
