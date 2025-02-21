from typing import TYPE_CHECKING, Self

from tortoise import fields

from pydentity.contrib.tortoise.base.model import Model
from pydentity.contrib.tortoise.fields import PersonalDataField
from pydentity.security.claims import Claim
from pydentity.user_login_info import UserLoginInfo

if TYPE_CHECKING:
    from datetime import datetime


__all__ = [
    "AbstractIdentityRole",
    "AbstractIdentityRoleClaim",
    "AbstractIdentityUser",
    "AbstractIdentityUserClaim",
    "AbstractIdentityUserLogin",
    "AbstractIdentityUserRole",
    "AbstractIdentityUserToken",
    "Model",
]


class AbstractIdentityUser(Model):
    if TYPE_CHECKING:
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
    else:
        access_failed_count = fields.IntField(default=0)
        concurrency_stamp = fields.TextField(null=True)
        email = PersonalDataField(256, null=True)
        email_confirmed = fields.BooleanField(default=False)
        id = fields.CharField(450, primary_key=True)
        lockout_enabled = fields.BooleanField(default=True)
        lockout_end = fields.DatetimeField(null=True)
        normalized_email = PersonalDataField(256, null=True)
        normalized_username = PersonalDataField(256, null=True)
        password_hash = fields.TextField(null=True)
        phone_number = PersonalDataField(256, null=True)
        phone_number_confirmed = fields.BooleanField(default=False)
        security_stamp = fields.UUIDField(null=True)
        two_factor_enabled = fields.BooleanField(default=False)
        username = PersonalDataField(256, null=True)

        class Meta:
            abstract = True

    def __str__(self) -> str:
        return self.username or self.email or str(self.id)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self!s} object at {hex(id(self))}>"


class AbstractIdentityRole(Model):
    if TYPE_CHECKING:
        concurrency_stamp: str | None
        id: str
        name: str | None
        normalized_name: str | None
    else:
        concurrency_stamp = fields.TextField(null=True)
        id = fields.CharField(450, primary_key=True)
        name = fields.CharField(256, null=True)
        normalized_name = fields.CharField(256, null=True)

        class Meta:
            abstract = True

    def __str__(self) -> str:
        return self.name or str(self.id)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self!s} object at {hex(id(self))}>"


class AbstractIdentityUserRole(Model):
    if TYPE_CHECKING:
        user_id: str
        role_id: str

    class Meta:
        abstract = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.role_id=}) object at {hex(id(self))}>"


class AbstractIdentityUserClaim(Model):
    if TYPE_CHECKING:
        claim_type: str
        claim_value: str | None
        user_id: str
    else:
        id = fields.IntField(primary_key=True)
        claim_type = fields.TextField()
        claim_value = fields.TextField(null=True)

        class Meta:
            abstract = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.claim_type=}) object at {hex(id(self))}>"

    def to_claim(self) -> Claim:
        return Claim(type=self.claim_type, value=self.claim_value)

    @classmethod
    def from_claim(cls, user_id: str, claim: Claim) -> Self:
        return cls(user_id=user_id, claim_type=claim.type, claim_value=claim.value)


class AbstractIdentityUserLogin(Model):
    if TYPE_CHECKING:
        login_provider: str
        provider_key: str
        provider_display_name: str | None
        user_id: str
    else:
        login_provider = fields.CharField(128)
        provider_key = fields.CharField(128)
        provider_display_name = fields.TextField(null=True)

        class Meta:
            abstract = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.login_provider=}) object at {hex(id(self))}>"

    def to_user_login_info(self) -> UserLoginInfo:
        return UserLoginInfo(
            login_provider=self.login_provider,
            provider_key=self.provider_key,
            provider_display_name=self.provider_display_name,
        )

    @classmethod
    def from_user_login_info(cls, user_id: str, login: UserLoginInfo) -> Self:
        return cls(
            user_id=user_id,
            login_provider=login.login_provider,
            provider_key=login.provider_key,
            provider_display_name=login.provider_display_name,
        )


class AbstractIdentityUserToken(Model):
    if TYPE_CHECKING:
        login_provider: str
        name: str
        value: str | None
        user_id: str
    else:
        login_provider = fields.CharField(128)
        name = fields.CharField(128)
        value = fields.TextField(null=True)

        class Meta:
            abstract = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.login_provider=}) object at {hex(id(self))}>"


class AbstractIdentityRoleClaim(Model):
    if TYPE_CHECKING:
        id: int
        claim_type: str
        claim_value: str | None
        role_id: str
    else:
        id = fields.IntField(primary_key=True)
        claim_type = fields.CharField(455)
        claim_value = fields.TextField(null=True)

        class Meta:
            abstract = True

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.role_id=}, {self.claim_type=}) object at {hex(id(self))}>"

    def to_claim(self) -> Claim:
        return Claim(type=self.claim_type, value=self.claim_value)

    @classmethod
    def from_claim(cls, role_id: str, claim: Claim) -> Self:
        return cls(role_id=role_id, claim_type=claim.type, claim_value=claim.value)
