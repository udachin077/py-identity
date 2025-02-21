from __future__ import annotations

from typing import Any
from uuid import uuid4

from tortoise import fields, indexes
from uuid_extensions import uuid7str

from pydentity.contrib.tortoise.base.abstract import (
    AbstractIdentityRole,
    AbstractIdentityRoleClaim,
    AbstractIdentityUser,
    AbstractIdentityUserClaim,
    AbstractIdentityUserLogin,
    AbstractIdentityUserRole,
    AbstractIdentityUserToken,
)
from pydentity.contrib.tortoise.base.model import Model

__all__ = [
    "IdentityRole",
    "IdentityRoleClaim",
    "IdentityUser",
    "IdentityUserClaim",
    "IdentityUserLogin",
    "IdentityUserRole",
    "IdentityUserToken",
    "Model",
]


class PersonalDataMixin:
    def __getattr__(self, item: Any) -> Any:
        if item == "__personal_data__":
            return getattr(self.Meta, "personal_data", ())
        raise AttributeError(f"{self.__class__.__name__!r} object has no attribute '{item!r}'")


class UniqueIndex(indexes.Index):
    INDEX_TYPE = "UNIQUE"


class IdentityUser(PersonalDataMixin, AbstractIdentityUser):
    """The default implementation of AbstractIdentityUser which uses a string as a primary key."""

    roles: fields.ManyToManyRelation[IdentityRole] = fields.ManyToManyField(
        "models.IdentityRole",
        related_name="users",
        through="pydentity_user_roles",
        forward_key="role_id",
        backward_key="user_id",
    )
    claims: fields.ReverseRelation[IdentityUserClaim]
    logins: fields.ReverseRelation[IdentityUserLogin]
    tokens: fields.ReverseRelation[IdentityUserToken]

    class Meta:
        table = "pydentity_users"
        unique_together = (("normalized_email",), ("normalized_username",))
        indexes = (
            UniqueIndex(fields=("normalized_email",), name="idx_pydentity_users_normalized_email"),
            UniqueIndex(fields=("normalized_username",), name="idx_pydentity_users_normalized_username"),
        )
        personal_data = (
            "id",
            "username",
            "email",
            "email_confirmed",
            "phone_number",
            "phone_number_confirmed",
            "two_factor_enabled",
        )

    def __init__(self, email: str, username: str | None = None, **kwargs: Any) -> None:
        super().__init__(
            id=uuid7str(),
            email=email,
            username=username,
            security_stamp=str(uuid4()),
            **kwargs,
        )


class IdentityRole(AbstractIdentityRole):
    """The default implementation of AbstractIdentityRole which uses a string as the primary key."""

    claims: fields.ReverseRelation[IdentityRoleClaim]
    users: fields.ReverseRelation[IdentityUser]

    class Meta:
        table = "pydentity_roles"
        unique_together = (("normalized_name",),)
        indexes = (UniqueIndex(fields=("normalized_name",), name="idx_pydentity_roles_normalized_name"),)

    def __init__(self, name: str, **kwargs: Any) -> None:
        super().__init__(id=uuid7str(), name=name, **kwargs)


class IdentityUserRole(AbstractIdentityUserRole):
    """Represents the link between a user and a role."""

    user = fields.ForeignKeyField("models.IdentityUser", to_field="id", on_delete=fields.CASCADE)
    role = fields.ForeignKeyField("models.IdentityRole", to_field="id", on_delete=fields.CASCADE)

    class Meta:
        table = "pydentity_user_roles"
        unique_together = (("user_id", "role_id"),)


class IdentityUserClaim(AbstractIdentityUserClaim):
    """Represents a claim that a user possesses."""

    user = fields.ForeignKeyField(
        "models.IdentityUser",
        to_field="id",
        on_delete=fields.CASCADE,
        related_name="claims",
    )

    class Meta:
        table = "pydentity_user_claims"


class IdentityUserLogin(AbstractIdentityUserLogin):
    """Represents a login and its associated provider for a user."""

    user = fields.ForeignKeyField(
        "models.IdentityUser",
        to_field="id",
        on_delete=fields.CASCADE,
        related_name="logins",
    )

    class Meta:
        table = "pydentity_user_logins"
        unique_together = (("login_provider", "provider_key"),)
        indexes = (UniqueIndex(fields=("login_provider", "provider_key"), name="idx_pydentity_user_logins_lp_pk"),)


class IdentityUserToken(AbstractIdentityUserToken):
    """Represents an authentication token for a user."""

    user = fields.ForeignKeyField(
        "models.IdentityUser",
        to_field="id",
        on_delete=fields.CASCADE,
        related_name="tokens",
    )

    class Meta:
        table = "pydentity_user_tokens"
        unique_together = (("user_id", "login_provider", "name"),)
        indexes = (
            UniqueIndex(fields=("user_id", "login_provider", "name"), name="idx_pydentity_user_tokens_user_lp_name"),
        )


class IdentityRoleClaim(AbstractIdentityRoleClaim):
    """Represents a claim that is granted to all users within a role."""

    role = fields.ForeignKeyField(
        "models.IdentityRole",
        to_field="id",
        on_delete=fields.CASCADE,
        related_name="claims",
    )

    class Meta:
        table = "pydentity_role_claims"
