from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, declared_attr, mapped_column, relationship
from uuid_extensions import uuid7str

from pydentity.contrib.sqlalchemy.base.abstract import (
    AbstractIdentityRole,
    AbstractIdentityRoleClaim,
    AbstractIdentityUser,
    AbstractIdentityUserClaim,
    AbstractIdentityUserLogin,
    AbstractIdentityUserRole,
    AbstractIdentityUserToken,
)
from pydentity.contrib.sqlalchemy.base.model import Model

__all__ = (
    "IdentityRole",
    "IdentityRoleClaim",
    "IdentityUser",
    "IdentityUserClaim",
    "IdentityUserLogin",
    "IdentityUserRole",
    "IdentityUserToken",
    "Model",
)


class IdentityUser(AbstractIdentityUser[str]):
    """The default implementation of AbstractIdentityUser which uses a string as a primary key."""

    __personal_data__ = (
        "id",
        "username",
        "email",
        "email_confirmed",
        "phone_number",
        "phone_number_confirmed",
        "two_factor_enabled",
    )

    if not TYPE_CHECKING:
        id: Mapped[str] = mapped_column(sa.String(450))

    @declared_attr
    def roles(self) -> Mapped[list[IdentityRole]]:
        return relationship(
            "IdentityRole",
            back_populates="users",
            secondary="pydentity_user_roles",
            cascade="all, delete",
        )

    @declared_attr
    def claims(self) -> Mapped[list[IdentityUserClaim]]:
        return relationship("IdentityUserClaim", back_populates="user", cascade="all, delete")

    @declared_attr
    def logins(self) -> Mapped[list[IdentityUserLogin]]:
        return relationship("IdentityUserLogin", back_populates="user", cascade="all, delete")

    @declared_attr
    def tokens(self) -> Mapped[list[IdentityUserToken]]:
        return relationship("IdentityUserToken", back_populates="user", cascade="all, delete")

    def __init__(self, email: str, username: str | None = None, **kwargs: Any) -> None:
        super().__init__(
            id=uuid7str(),
            email=email,
            username=username,
            security_stamp=str(uuid4()),
            **kwargs,
        )


class IdentityRole(AbstractIdentityRole[str]):
    """The default implementation of AbstractIdentityRole which uses a string as the primary key."""

    if not TYPE_CHECKING:
        id: Mapped[str] = mapped_column(sa.String(450))

    @declared_attr
    def users(self) -> Mapped[list[IdentityUser]]:
        return relationship("IdentityUser", back_populates="roles", secondary="pydentity_user_roles")

    @declared_attr
    def claims(self) -> Mapped[list[IdentityRoleClaim]]:
        return relationship("IdentityRoleClaim", back_populates="role", cascade="all, delete")

    def __init__(self, name: str, **kwargs: Any) -> None:
        super().__init__(id=uuid7str(), name=name, **kwargs)


class IdentityUserRole(AbstractIdentityUserRole[str, str]):
    """Represents the link between a user and a role."""


class IdentityUserClaim(AbstractIdentityUserClaim[str]):
    """Represents a claim that a user possesses."""

    @declared_attr
    def user(self) -> Mapped[IdentityUser]:
        return relationship("IdentityUser", back_populates="claims")


class IdentityUserLogin(AbstractIdentityUserLogin[str]):
    """Represents a login and its associated provider for a user."""

    @declared_attr
    def user(self) -> Mapped[IdentityUser]:
        return relationship("IdentityUser", back_populates="logins")


class IdentityUserToken(AbstractIdentityUserToken[str]):
    """Represents an authentication token for a user."""

    @declared_attr
    def user(self) -> Mapped[IdentityUser]:
        return relationship("IdentityUser", back_populates="tokens")


class IdentityRoleClaim(AbstractIdentityRoleClaim[str]):
    """Represents a claim that is granted to all users within a role."""

    @declared_attr
    def role(self) -> Mapped[IdentityRole]:
        return relationship("IdentityRole", back_populates="claims")
