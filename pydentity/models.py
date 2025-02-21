from datetime import datetime
from typing import Protocol, Self, TypeVar

__all__ = [
    "RoleClaimProtokol",
    "RoleClaimT",
    "RoleProtokol",
    "RoleT",
    "UserClaimProtokol",
    "UserClaimT",
    "UserLoginProtokol",
    "UserLoginT",
    "UserProtokol",
    "UserRoleProtokol",
    "UserRoleT",
    "UserT",
    "UserTokenProtokol",
    "UserTokenT",
]

from pydentity.security.claims import Claim
from pydentity.user_login_info import UserLoginInfo


class UserProtokol(Protocol):
    access_failed_count: int
    concurrency_stamp: str | None
    email: str | None
    email_confirmed: bool
    id: str
    lockout_enabled: bool
    lockout_end: datetime | None
    normalized_email: str | None
    normalized_username: str | None
    password_hash: str | None
    phone_number: str | None
    phone_number_confirmed: bool
    security_stamp: str | None
    two_factor_enabled: bool
    username: str | None


class RoleProtokol(Protocol):
    concurrency_stamp: str | None
    id: str
    name: str | None
    normalized_name: str | None


class UserRoleProtokol(Protocol):
    user_id: str
    role_id: str


class UserClaimProtokol(Protocol):
    claim_type: str
    claim_value: str | None
    user_id: str

    def to_claim(self) -> Claim: ...

    @classmethod
    def from_claim(cls, user_id: str, claim: Claim) -> Self: ...


class UserLoginProtokol(Protocol):
    login_provider: str
    provider_key: str
    provider_display_name: str | None
    user_id: str

    def to_user_login_info(self) -> UserLoginInfo: ...

    @classmethod
    def from_user_login_info(cls, user_id: str, user_login_info: UserLoginInfo) -> Self: ...


class UserTokenProtokol(Protocol):
    login_provider: str
    name: str
    value: str | None
    user_id: str


class RoleClaimProtokol(Protocol):
    claim_type: str
    claim_value: str | None
    role_id: str

    def to_claim(self) -> Claim: ...

    @classmethod
    def from_claim(cls, role_id: str, claim: Claim) -> Self: ...


UserT = TypeVar("UserT", bound=UserProtokol)
RoleT = TypeVar("RoleT", bound=RoleProtokol)
UserRoleT = TypeVar("UserRoleT", bound=UserRoleProtokol)
UserClaimT = TypeVar("UserClaimT", bound=UserClaimProtokol)
UserLoginT = TypeVar("UserLoginT", bound=UserLoginProtokol)
UserTokenT = TypeVar("UserTokenT", bound=UserTokenProtokol)
RoleClaimT = TypeVar("RoleClaimT", bound=RoleClaimProtokol)
