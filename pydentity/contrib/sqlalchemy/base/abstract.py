from __future__ import annotations

from datetime import datetime  # noqa: TC003
from typing import TYPE_CHECKING, Self

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from pydentity.contrib.sqlalchemy.base.model import Model
from pydentity.contrib.sqlalchemy.fields import PersonalDataField
from pydentity.security.claims import Claim
from pydentity.user_login_info import UserLoginInfo

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


class AbstractIdentityUser[UserKeyT](Model):
    __abstract__ = True
    __tablename__ = "pydentity_users"
    __table_args__ = (
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("normalized_email"),
        sa.UniqueConstraint("normalized_username"),
        sa.Index("idx_pydentity_users_normalized_email", "normalized_email", unique=True),
        sa.Index(
            "idx_pydentity_users_normalized_username",
            "normalized_username",
            unique=True,
        ),
        {"extend_existing": True},
    )

    if TYPE_CHECKING:
        access_failed_count: int
        concurrency_stamp: str | None
        email: str | None
        email_confirmed: bool
        id: UserKeyT
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
        access_failed_count: Mapped[int] = mapped_column(sa.Integer, default=0)
        concurrency_stamp: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
        email: Mapped[str | None] = mapped_column(PersonalDataField(256), nullable=True)
        email_confirmed: Mapped[bool] = mapped_column(sa.Boolean, default=False)
        lockout_enabled: Mapped[bool] = mapped_column(sa.Boolean, default=True)
        lockout_end: Mapped[datetime | None] = mapped_column(sa.TIMESTAMP, nullable=True)
        normalized_email: Mapped[str | None] = mapped_column(PersonalDataField(256), nullable=True)
        normalized_username: Mapped[str | None] = mapped_column(PersonalDataField(256), nullable=True)
        password_hash: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
        phone_number: Mapped[str | None] = mapped_column(PersonalDataField(256), nullable=True)
        phone_number_confirmed: Mapped[bool] = mapped_column(sa.Boolean, default=False)
        security_stamp: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
        two_factor_enabled: Mapped[bool] = mapped_column(sa.Boolean, default=False)
        username: Mapped[str | None] = mapped_column(PersonalDataField(256), nullable=True)

    def __str__(self) -> str:
        return self.username or self.email or str(self.id)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self!s} object at {hex(id(self))}>"


class AbstractIdentityRole[RoleKeyT](Model):
    __abstract__ = True
    __tablename__ = "pydentity_roles"
    __table_args__ = (
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("normalized_name"),
        sa.Index("idx_pydentity_roles_normalized_name", "normalized_name", unique=True),
        {"extend_existing": True},
    )

    if TYPE_CHECKING:
        concurrency_stamp: str | None
        id: RoleKeyT
        name: str | None
        normalized_name: str | None
    else:
        concurrency_stamp: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
        name: Mapped[str | None] = mapped_column(sa.String(256), nullable=True)
        normalized_name: Mapped[str | None] = mapped_column(sa.String(256), nullable=True)

    def __str__(self) -> str:
        return self.name or str(self.id)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self!s} object at {hex(id(self))}>"


class AbstractIdentityUserRole[UserKeyT, RoleKeyT](Model):
    __abstract__ = True
    __tablename__ = "pydentity_user_roles"
    __table_args__ = (
        sa.PrimaryKeyConstraint("user_id", "role_id"),
        {"extend_existing": True},
    )

    if TYPE_CHECKING:
        user_id: UserKeyT
        role_id: RoleKeyT
    else:
        user_id = mapped_column(sa.ForeignKey("pydentity_users.id", ondelete="CASCADE"))
        role_id = mapped_column(sa.ForeignKey("pydentity_roles.id", ondelete="CASCADE"))

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.role_id=}) object at {hex(id(self))}>"


class AbstractIdentityUserClaim[UserKeyT](Model):
    __abstract__ = True
    __tablename__ = "pydentity_user_claims"
    __table_args__ = {"extend_existing": True}

    if TYPE_CHECKING:
        claim_type: str
        claim_value: str | None
        user_id: UserKeyT
    else:
        id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
        claim_type: Mapped[str] = mapped_column(sa.Text)
        claim_value: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
        user_id = mapped_column(sa.ForeignKey("pydentity_users.id", ondelete="CASCADE"))

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.claim_type=}) object at {hex(id(self))}>"

    def to_claim(self) -> Claim:
        return Claim(type=self.claim_type, value=self.claim_value)

    @classmethod
    def from_claim(cls, user_id: UserKeyT, claim: Claim) -> Self:
        return cls(user_id=user_id, claim_type=claim.type, claim_value=claim.value)


class AbstractIdentityUserLogin[UserKeyT](Model):
    __abstract__ = True
    __tablename__ = "pydentity_user_logins"
    __table_args__ = (
        sa.PrimaryKeyConstraint("login_provider", "provider_key"),
        {"extend_existing": True},
    )

    if TYPE_CHECKING:
        login_provider: str
        provider_key: str
        provider_display_name: str | None
        user_id: UserKeyT
    else:
        login_provider: Mapped[str] = mapped_column(sa.String(128))
        provider_key: Mapped[str] = mapped_column(sa.String(128))
        provider_display_name: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
        user_id = mapped_column(sa.ForeignKey("pydentity_users.id", ondelete="CASCADE"))

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.login_provider=}) object at {hex(id(self))}>"

    def to_user_login_info(self) -> UserLoginInfo:
        return UserLoginInfo(
            login_provider=self.login_provider,
            provider_key=self.provider_key,
            provider_display_name=self.provider_display_name,
        )

    @classmethod
    def from_user_login_info(cls, user_id: UserKeyT, login: UserLoginInfo) -> Self:
        return cls(
            user_id=user_id,
            login_provider=login.login_provider,
            provider_key=login.provider_key,
            provider_display_name=login.provider_display_name,
        )


class AbstractIdentityUserToken[UserKeyT](Model):
    __abstract__ = True
    __tablename__ = "pydentity_user_tokens"
    __table_args__ = (
        sa.PrimaryKeyConstraint("user_id", "login_provider", "name"),
        {"extend_existing": True},
    )

    if TYPE_CHECKING:
        login_provider: str
        name: str
        value: str | None
        user_id: UserKeyT
    else:
        user_id = mapped_column(sa.ForeignKey("pydentity_users.id", ondelete="CASCADE"))
        login_provider: Mapped[str] = mapped_column(sa.String(128))
        name: Mapped[str] = mapped_column(sa.String(128))
        value: Mapped[str | None] = mapped_column(sa.Text, nullable=True)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.user_id=}, {self.login_provider=}) object at {hex(id(self))}>"


class AbstractIdentityRoleClaim[RoleKeyT](Model):
    __abstract__ = True
    __tablename__ = "pydentity_role_claims"
    __table_args__ = {"extend_existing": True}

    if TYPE_CHECKING:
        id: int
        claim_type: str
        claim_value: str | None
        role_id: RoleKeyT
    else:
        id: Mapped[int] = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
        claim_type: Mapped[str] = mapped_column(sa.String(455))
        claim_value: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
        role_id = mapped_column(sa.ForeignKey("pydentity_roles.id", ondelete="CASCADE"))

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} ({self.role_id=}, {self.claim_type=}) object at {hex(id(self))}>"

    def to_claim(self) -> Claim:
        return Claim(type=self.claim_type, value=self.claim_value)

    @classmethod
    def from_claim(cls, role_id: RoleKeyT, claim: Claim) -> Self:
        return cls(role_id=role_id, claim_type=claim.type, claim_value=claim.value)
