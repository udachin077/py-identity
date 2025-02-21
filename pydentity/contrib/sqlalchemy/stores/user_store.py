from datetime import datetime, timezone
from typing import Any, Final, Generic
from uuid import uuid4

from sqlalchemy import Executable, and_, delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

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
from pydentity.models import (
    RoleT,
    UserClaimT,
    UserLoginT,
    UserRoleT,
    UserT,
    UserTokenT,
)
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

    auto_save_changes: bool = True

    def __init__(self, session: AsyncSession, error_describer: IdentityErrorDescriber | None = None) -> None:
        self.session: AsyncSession = session
        self.error_describer = error_describer or IdentityErrorDescriber()

    def create_model_from_dict(self, **kwargs: Any) -> UserT:
        return self.users(**kwargs)

    async def save_changes(self) -> None:
        """Saves the current store."""
        self.auto_save_changes and await self.session.commit()

    async def refresh(self, user: UserT) -> None:
        if user is None:
            raise ArgumentNoneError("user")

        await self.session.refresh(user)

    async def all(self) -> list[UserT]:
        return list((await self.session.scalars(select(self.users))).all())

    async def create(self, user: UserT) -> IdentityResult:
        if user is None:
            raise ArgumentNoneError("user")

        self.session.add(user)
        await self.save_changes()
        await self.refresh(user)
        return IdentityResult.success()

    async def update(self, user: UserT) -> IdentityResult:
        if user is None:
            raise ArgumentNoneError("user")

        stmt = select(self.users).where(
            and_(
                self.users.id == user.id,  # type: ignore
                self.users.concurrency_stamp == user.concurrency_stamp,  # type: ignore
            )
        )

        if not (await self.session.execute(stmt)).one_or_none():
            return IdentityResult.failed(self.error_describer.ConcurrencyFailure())

        user.concurrency_stamp = str(uuid4())
        self.session.add(user)
        await self.save_changes()
        await self.refresh(user)
        return IdentityResult.success()

    async def delete(self, user: UserT) -> IdentityResult:
        if user is None:
            raise ArgumentNoneError("user")

        await self.session.delete(user)
        await self.save_changes()
        return IdentityResult.success()

    async def find_by_id(self, user_id: str) -> UserT | None:
        if user_id is None:
            raise ArgumentNoneError("user_id")

        return await self._find_user(select(self.users).where(self.users.id == user_id))  # type:ignore

    async def find_by_name(self, normalized_username: str) -> UserT | None:
        if normalized_username is None:
            raise ArgumentNoneError("normalized_username")

        return await self._find_user(select(self.users).where(self.users.normalized_username == normalized_username))  # type:ignore

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

        return await self._find_user(
            select(self.users).where(
                self.users.normalized_email == normalized_email  # type: ignore
            )
        )

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
        return user.access_failed_count

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
            await self.session.execute(insert(self.user_roles).values(user_id=user.id, role_id=role.id))
            return

        raise InvalidOperationError(Resources.RoleNotFound.format(normalized_role_name))

    async def get_roles(self, user: UserT) -> list[str]:
        if user is None:
            raise ArgumentNoneError("user")

        query = select(self.roles.name).where(
            and_(
                self.users.id == user.id,  # type:ignore
                self.users.id == self.user_roles.user_id,
                self.roles.id == self.user_roles.role_id,
            )
        )
        roles = await self.session.scalars(query)
        return list(roles.all())

    async def get_users_in_role(self, normalized_role_name: str) -> list[UserT]:
        if normalized_role_name is None:
            raise ArgumentNoneError("normalized_role_name")

        if role := await self._find_role(normalized_role_name):
            users: list[UserT] = await role.awaitable_attrs.users
            return users

        raise InvalidOperationError(Resources.RoleNotFound.format(normalized_role_name))

    async def is_in_role(self, user: UserT, normalized_role_name: str) -> bool:
        if user is None:
            raise ArgumentNoneError("user")
        if normalized_role_name is None:
            raise ArgumentNoneError("normalized_role_name")

        if role := await self._find_role(normalized_role_name):
            query = select(self.user_roles).where(
                and_(
                    self.user_roles.user_id == user.id,
                    self.user_roles.role_id == role.id,
                )
            )
            result = await self.session.scalars(query)
            return bool(result.one_or_none())

        return False

    async def remove_from_role(self, user: UserT, normalized_role_name: str) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if normalized_role_name is None:
            raise ArgumentNoneError("normalized_role_name")

        if role := await self._find_role(normalized_role_name):
            query = delete(self.user_roles).where(
                and_(
                    self.user_roles.user_id == user.id,
                    self.user_roles.role_id == role.id,
                )
            )
            await self.session.execute(query)

    async def add_login(self, user: UserT, login: UserLoginInfo) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if login is None:
            raise ArgumentNoneError("login")

        self.session.add(self.user_logins.from_user_login_info(user.id, login))
        await self.save_changes()

    async def find_by_login(self, login_provider: str, provider_key: str) -> UserT | None:
        if login_provider is None:
            raise ArgumentNoneError("login_provider")
        if provider_key is None:
            raise ArgumentNoneError("provider_key")

        query = select(self.user_logins).where(
            and_(
                self.user_logins.login_provider == login_provider,
                self.user_logins.provider_key == provider_key,
            )
        )

        if user_login := (await self.session.scalars(query)).one_or_none():
            return await self._find_user(select(self.users).where(self.users.id == user_login.user_id))

        return None

    async def get_logins(self, user: UserT) -> list[UserLoginInfo]:
        if user is None:
            raise ArgumentNoneError("user")

        query = select(self.user_logins).where(self.user_logins.user_id == user.id)  # type:ignore
        user_logins = await self.session.scalars(query)
        return [ul.to_user_login_info() for ul in user_logins.all()]

    async def remove_login(self, user: UserT, login_provider: str, provider_key: str) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if login_provider is None:
            raise ArgumentNoneError("login_provider")
        if provider_key is None:
            raise ArgumentNoneError("provider_key")

        query = delete(self.user_logins).where(
            and_(
                self.user_logins.user_id == user.id,
                self.user_logins.login_provider == login_provider,
                self.user_logins.provider_key == provider_key,
            )
        )
        await self.session.execute(query)

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

        query = delete(self.user_tokens).where(
            and_(
                self.user_tokens.user_id == user.id,
                self.user_tokens.login_provider == login_provider,
                self.user_tokens.name == name,
            )
        )
        await self.session.execute(query)

    async def set_token(self, user: UserT, login_provider: str, name: str, value: str | None) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if login_provider is None:
            raise ArgumentNoneError("login_provider")
        if name is None:
            raise ArgumentNoneError("name")

        if token := await self._find_token(user, login_provider, name):
            token.value = value
            await self.save_changes()
            return

        self.session.add(self.user_tokens(user_id=user.id, login_provider=login_provider, name=name, value=value))
        await self.save_changes()

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

        return await self.set_token(
            user,
            self.INTERNAL_LOGIN_PROVIDER,
            self.RECOVERY_CODE_TOKEN_NAME,
            ";".join(recovery_codes),
        )

    async def add_claims(self, user: UserT, *claims: Claim) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if not claims:
            raise ArgumentNoneError("claims")

        self.session.add_all(self.user_claims.from_claim(user.id, claim) for claim in claims)
        await self.save_changes()

    async def get_claims(self, user: UserT) -> list[Claim]:
        if user is None:
            raise ArgumentNoneError("user")

        query = select(self.user_claims).where(self.user_claims.user_id == user.id)  # type:ignore
        user_claims = (await self.session.scalars(query)).all()
        return [uc.to_claim() for uc in user_claims]

    async def get_users_for_claim(self, claim: Claim) -> list[UserT]:
        if claim is None:
            raise ArgumentNoneError("claim")

        query = select(self.user_claims).where(
            and_(
                self.user_claims.claim_type == claim.type,
                self.user_claims.claim_value == claim.value,
            )
        )
        user_claims = await self.session.scalars(query)
        return [await uc.awaitable_attrs.user for uc in user_claims.all()]

    async def remove_claims(self, user: UserT, *claims: Claim) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if not claims:
            raise ArgumentNoneError("claims")

        for claim in claims:
            query = select(self.user_claims).where(
                and_(
                    self.user_claims.user_id == user.id,
                    self.user_claims.claim_type == claim.type,
                    self.user_claims.claim_value == claim.value,
                )
            )

            matches_claims = (await self.session.scalars(query)).all()
            for c in matches_claims:
                await self.session.delete(c)
        await self.save_changes()

    async def replace_claim(self, user: UserT, claim: Claim, new_claim: Claim) -> None:
        if user is None:
            raise ArgumentNoneError("user")
        if claim is None:
            raise ArgumentNoneError("claim")
        if new_claim is None:
            raise ArgumentNoneError("new_claim")

        query = (
            update(self.user_claims)
            .where(
                and_(
                    self.user_claims.user_id == user.id,
                    self.user_claims.claim_type == claim.type,
                    self.user_claims.claim_value == claim.value,
                )
            )
            .values(claim_type=new_claim.type, claim_value=new_claim.value)
        )
        await self.session.execute(query)

    async def get_personal_data(self, user: UserT) -> dict[str, Any] | None:
        if user is None:
            raise ArgumentNoneError("user")

        cls = user.__class__
        if hasattr(cls, "__personal_data__"):
            return {p: getattr(user, p) for p in cls.__personal_data__}

        raise PersonalDataError(
            f"The model '{cls}' does not support receiving personal data.\n"
            f"The model must have the '__personal_data__' attribute, "
            f"which lists the fields related to personal data."
        )

    async def _find_token(self, user: UserT, login_provider: str, name: str) -> UserTokenT | None:
        query = select(self.user_tokens).where(
            and_(
                self.user_tokens.user_id == user.id,
                self.user_tokens.login_provider == login_provider,
                self.user_tokens.name == name,
            )
        )
        result = await self.session.scalars(query)
        return result.one_or_none()

    async def _find_user(self, query: Executable) -> UserT | None:
        result = await self.session.scalars(query)
        return result.one_or_none()

    async def _find_role(self, name: str) -> RoleT | None:
        result = await self.session.scalars(
            select(self.roles).where(self.roles.normalized_name == name)  # type: ignore
        )
        return result.one_or_none()
