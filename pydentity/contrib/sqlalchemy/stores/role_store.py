from typing import TYPE_CHECKING, Any, Generic
from uuid import uuid4

from sqlalchemy import and_, delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from pydentity.abc.stores import IRoleClaimStore, IRoleStore
from pydentity.exc import ArgumentNoneError
from pydentity.identity_error_describer import IdentityErrorDescriber
from pydentity.identity_result import IdentityResult
from pydentity.models import RoleClaimT, RoleT
from pydentity.security.claims import Claim

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = ["RoleStore"]


class RoleStore(IRoleClaimStore[RoleT], IRoleStore[RoleT], Generic[RoleT]):
    roles: type[RoleT]
    role_claims: type[RoleClaimT]

    auto_save_changes: bool = True

    def __init__(self, session: AsyncSession, error_describer: IdentityErrorDescriber | None = None) -> None:
        self.session = session
        self.error_describer = error_describer or IdentityErrorDescriber()

    def create_model_from_dict(self, **kwargs: Any) -> RoleT:
        return self.roles(**kwargs)

    async def save_changes(self) -> None:
        self.auto_save_changes and await self.session.commit()

    async def refresh(self, role: RoleT) -> None:
        if role is None:
            raise ArgumentNoneError("role")

        await self.session.refresh(role)

    async def all(self) -> list[RoleT]:
        return list((await self.session.scalars(select(self.roles))).all())

    async def create(self, role: RoleT) -> IdentityResult:
        if role is None:
            raise ArgumentNoneError("role")

        self.session.add(role)
        await self.save_changes()
        await self.refresh(role)
        return IdentityResult.success()

    async def update(self, role: RoleT) -> IdentityResult:
        if role is None:
            raise ArgumentNoneError("role")

        stmt = select(self.roles).where(
            and_(
                self.roles.id == role.id,  # type: ignore
                self.roles.concurrency_stamp == role.concurrency_stamp,  # type: ignore
            )
        )

        if not (await self.session.execute(stmt)).one_or_none():
            return IdentityResult.failed(self.error_describer.ConcurrencyFailure())

        role.concurrency_stamp = str(uuid4())
        self.session.add(role)
        await self.save_changes()
        await self.refresh(role)
        return IdentityResult.success()

    async def delete(self, role: RoleT) -> IdentityResult:
        if role is None:
            raise ArgumentNoneError("role")

        await self.session.delete(role)
        await self.save_changes()
        return IdentityResult.success()

    async def find_by_id(self, role_id: str) -> RoleT | None:
        if role_id is None:
            raise ArgumentNoneError("role_id")

        statement = select(self.roles).where(self.roles.id == role_id)  # type:ignore
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def find_by_name(self, normalized_name: str) -> RoleT | None:
        if normalized_name is None:
            raise ArgumentNoneError("normalized_name")

        statement = select(self.roles).where(self.roles.normalized_name == normalized_name)  # type: ignore
        result = await self.session.execute(statement)
        return result.scalar_one_or_none()

    async def get_role_id(self, role: RoleT) -> str:
        if role is None:
            raise ArgumentNoneError("role")

        return role.id

    async def get_role_name(self, role: RoleT) -> str | None:
        if role is None:
            raise ArgumentNoneError("role")

        return role.name

    async def set_role_name(self, role: RoleT, role_name: str | None) -> None:
        if role_name is None:
            raise ArgumentNoneError("role_name")

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

        self.session.add(self.role_claims.from_claim(role.id, claim))
        await self.save_changes()

    async def remove_claim(self, role: RoleT, claim: Claim) -> None:
        if role is None:
            raise ArgumentNoneError("role")
        if claim is None:
            raise ArgumentNoneError("claim")
        statement = delete(self.role_claims).where(
            and_(
                self.role_claims.role_id == role.id,
                self.role_claims.claim_type == claim.type,  # type:ignore
                self.role_claims.claim_value == claim.value,
            )
        )
        await self.session.execute(statement)

    async def get_claims(self, role: RoleT) -> list[Claim]:
        if role is None:
            raise ArgumentNoneError("role")

        statement = select(self.role_claims).where(self.role_claims.role_id == role.id)  # type: ignore
        role_claims: Sequence[RoleClaimT] = (await self.session.scalars(statement)).all()
        return [uc.to_claim() for uc in role_claims]
