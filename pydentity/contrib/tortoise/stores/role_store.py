from typing import Any, Generic
from uuid import uuid4

from tortoise.backends.base.client import BaseDBAsyncClient

from pydentity.abc.stores import IRoleClaimStore, IRoleStore
from pydentity.exc import ArgumentNoneError
from pydentity.identity_error_describer import IdentityErrorDescriber
from pydentity.identity_result import IdentityResult
from pydentity.models import RoleClaimT, RoleT
from pydentity.security.claims import Claim

__all__ = ["RoleStore"]


class RoleStore(IRoleClaimStore[RoleT], IRoleStore[RoleT], Generic[RoleT]):
    roles: type[RoleT]
    role_claims: type[RoleClaimT]

    def __init__(
        self, using_db: BaseDBAsyncClient | None = None, error_describer: IdentityErrorDescriber | None = None
    ) -> None:
        self.using_db = using_db
        self.error_describer = error_describer or IdentityErrorDescriber()

    def create_model_from_dict(self, **kwargs: Any) -> RoleT:
        return self.roles(**kwargs)

    async def refresh(self, role: RoleT):
        if role is None:
            raise ArgumentNoneError("role")

        await role.refresh_from_db(using_db=self.using_db)

    async def all(self) -> list[RoleT]:
        return await self.roles.all(using_db=self.using_db)

    async def create(self, role: RoleT) -> IdentityResult:
        if role is None:
            raise ArgumentNoneError("role")

        await role.save(using_db=self.using_db)
        await self.refresh(role)
        return IdentityResult.success()

    async def update(self, role: RoleT) -> IdentityResult:
        if role is None:
            raise ArgumentNoneError("role")

        if not await self.roles.filter(id=role.id, concurrency_stamp=role.concurrency_stamp).exists():
            return IdentityResult.failed(self.error_describer.ConcurrencyFailure())

        role.concurrency_stamp = str(uuid4())
        await role.save(using_db=self.using_db)
        await self.refresh(role)
        return IdentityResult.success()

    async def delete(self, role: RoleT) -> IdentityResult:
        if role is None:
            raise ArgumentNoneError("role")

        await role.delete(using_db=self.using_db)
        return IdentityResult.success()

    async def find_by_id(self, role_id: Any) -> RoleT | None:
        if role_id is None:
            raise ArgumentNoneError("role_id")

        return await self.roles.get_or_none(id=role_id, using_db=self.using_db)

    async def find_by_name(self, normalized_name: str) -> RoleT | None:
        if normalized_name is None:
            raise ArgumentNoneError("normalized_name")

        return await self.roles.get_or_none(normalized_name=normalized_name, using_db=self.using_db)

    async def get_role_id(self, role: RoleT) -> Any:
        if role is None:
            raise ArgumentNoneError("role")

        return role.id

    async def get_role_name(self, role: RoleT) -> str | None:
        if role is None:
            raise ArgumentNoneError("role")

        return role.name

    async def set_role_name(self, role: RoleT, role_name: str | None) -> None:
        if role is None:
            raise ArgumentNoneError("role")

        role.name = role_name

    async def get_normalized_role_name(self, role: RoleT) -> str | None:
        if role is None:
            raise ArgumentNoneError("role")

        return role.normalized_name

    async def set_normalized_role_name(self, role: RoleT, normalized_name: str | None) -> None:
        if role is None:
            raise ArgumentNoneError("role")

        role.normalized_name = normalized_name

    async def add_claim(self, role: RoleT, claim: Claim) -> None:
        if role is None:
            raise ArgumentNoneError("role")
        if claim is None:
            raise ArgumentNoneError("claim")

        await self.role_claims(role_id=role.id, claim_type=claim.type, claim_value=claim.value).save(self.using_db)

    async def remove_claim(self, role: RoleT, claim: Claim) -> None:
        if role is None:
            raise ArgumentNoneError("role")
        if claim is None:
            raise ArgumentNoneError("claim")

        await (
            self.role_claims.filter(role_id=role.id, claim_type=claim.type, claim_value=claim.value)
            .using_db(self.using_db)
            .delete()
        )

    async def get_claims(self, role: RoleT) -> list[Claim]:
        if role is None:
            raise ArgumentNoneError("role")

        result = await (
            self.role_claims.filter(role_id=role.id).using_db(self.using_db).values_list("claim_type", "claim_value")
        )
        return [Claim(*r) for r in result]
