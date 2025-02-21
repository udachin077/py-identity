from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Generic, cast

from pydentity.abc.stores import IRoleClaimStore, IRoleStore
from pydentity.exc import ArgumentNoneError, NotSupportedError
from pydentity.identity_error_describer import IdentityErrorDescriber
from pydentity.identity_result import IdentityResult
from pydentity.models import RoleT
from pydentity.resources import Resources

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pydentity.abc.lookup_normalizer import ILookupNormalizer
    from pydentity.abc.validators import IRoleValidator
    from pydentity.identity_error import IdentityError
    from pydentity.security.claims import Claim

__all__ = ["RoleManager"]


class RoleManager(Generic[RoleT]):
    """Provides the APIs for managing roles in a persistence store."""

    __slots__ = ("error_describer", "key_normalizer", "logger", "role_validators", "store")

    def __init__(
        self,
        role_store: IRoleStore[RoleT],
        role_validators: Iterable[IRoleValidator[RoleT]] | None = None,
        key_normalizer: ILookupNormalizer | None = None,
        error_describer: IdentityErrorDescriber | None = None,
    ) -> None:
        """Constructs a new instance of *RoleManager[TRole]*.

        :param role_store: The persistence store the manager will operate over.
        :param role_validators: A collection of validators for roles.
        :param key_normalizer: The normalizer to use when normalizing role names to keys.
        :param error_describer: The *IdentityErrorDescriber* used to provider error messages.
        """
        if role_store is None:
            raise ArgumentNoneError("role_store")

        self.store = role_store
        """Gets or sets the persistence store the manager operate over."""
        self.role_validators = role_validators
        """Gets or sets *IRoleValidator[TRole]* the validators for roles."""
        self.key_normalizer = key_normalizer
        """Gets or sets *ILookupNormalizer* used to normalize things like role names."""
        self.error_describer: IdentityErrorDescriber = error_describer or IdentityErrorDescriber()
        """Gets or sets *IdentityErrorDescriber* used to generate error messages."""
        self.logger = logging.getLogger("PyIdentity.RoleManager")
        """Gets or sets logger used to log messages from the manager."""

    @property
    def supports_role_claims(self) -> bool:
        """Gets a flag indicating whether the underlying persistence store supports *Claims* for roles.

        :return: *True* if *Claims* for roles are supported, *False* otherwise.
        """
        return issubclass(type(self.store), IRoleClaimStore)

    async def all(self) -> list[RoleT]:
        """Get all roles.

        :return: Returns a list of all roles.
        """
        return await self.store.all()

    async def create(self, role: RoleT) -> IdentityResult:
        """Create the specified role.

        :param role: The role to create.
        :return: Result of the operation.
        """
        if role is None:
            raise ArgumentNoneError("role")

        result = await self._validate_role(role)
        if not result.succeeded:
            return result

        await self.update_normalized_role_name(role)
        return await self.store.create(role)

    async def update(self, role: RoleT) -> IdentityResult:
        """Updates the specified role.

        :param role: The role to update.
        :return: Return result of the operation.
        """
        if role is None:
            raise ArgumentNoneError("role")

        return await self._update_role(role)

    async def delete(self, role: RoleT) -> IdentityResult:
        """Deletes the specified role.

        :param role: The role to delete.
        :return: Return result of the operation.
        """
        if role is None:
            raise ArgumentNoneError("role")

        return await self.store.delete(role)

    async def role_exists(self, role_name: str) -> bool:
        """Gets a flag indicating whether the specified *role_name* exists.

        :param role_name: The role name whose existence should be checked.
        :return: *True* if *role_name* exists, *False* otherwise.
        """
        if role_name is None:
            raise ArgumentNoneError("role_name")

        return await self.find_by_name(role_name) is not None

    async def get_role_id(self, role: RoleT) -> str:
        """Gets the ID of the specified role.

        :param role: The role whose ID should be retrieved
        :return: Returns the ID of the specified role.
        """
        if role is None:
            raise ArgumentNoneError("role")

        return await self.store.get_role_id(role)

    async def find_by_id(self, role_id: str) -> RoleT | None:
        """Finds the role associated with the specified *role_id* if any.

        :param role_id: The role ID whose role should be returned.
        :return: Returns the role if found, None otherwise.
        """
        if role_id is None:
            raise ArgumentNoneError("role_id")

        return await self.store.find_by_id(role_id)

    async def get_role_name(self, role: RoleT) -> str | None:
        """Gets the name of the specified role.

        :param role: The role whose name should be retrieved.
        :return: Returns the name of the role.
        """
        if role is None:
            raise ArgumentNoneError("role")

        return await self.store.get_role_name(role)

    async def set_role_name(self, role: RoleT, name: str | None = None) -> IdentityResult:
        """Sets the name of the specified role.

        :param role: The role whose name should be set.
        :param name: The name to set.
        :return: Returns the result of the operation.
        """
        if role is None:
            raise ArgumentNoneError("role")

        await self.store.set_role_name(role, name)
        await self.update_normalized_role_name(role)
        return IdentityResult.success()

    async def find_by_name(self, role_name: str) -> RoleT | None:
        """Finds the role associated with the specified *role_name* if any.

        :param role_name: The name of the role to be returned.
        :return: Returns the role or None if it was not found.
        """
        if not role_name:
            raise ArgumentNoneError("role_name")

        return await self.store.find_by_name(self._normalize_key(role_name))  # type: ignore[arg-type]

    async def update_normalized_role_name(self, role: RoleT) -> None:
        """Updates the normalized name for the specified role.

        :param role: The role whose normalized name needs to be updated.
        :return: Returns the result of the operation.
        """
        if role is None:
            raise ArgumentNoneError("role")

        name = await self.store.get_role_name(role)
        await self.store.set_normalized_role_name(role, self._normalize_key(name))

    async def get_claims(self, role: RoleT) -> list[Claim]:
        """Gets a list of claims associated with the specified role.

        :param role: The role whose claims should be returned.
        :return: Returns a list of claims.
        """
        if role is None:
            raise ArgumentNoneError("role")

        return await self._get_claim_store().get_claims(role)

    async def add_claim(self, role: RoleT, claim: Claim) -> IdentityResult:
        """Adds a claim to a role.

        :param role: The role whose claim should be added.
        :param claim: The claim to add.
        :return: Returns the result of the operation.
        """
        if role is None:
            raise ArgumentNoneError("role")
        if claim is None:
            raise ArgumentNoneError("claim")

        store = self._get_claim_store()
        await store.add_claim(role, claim)
        return await self._update_role(role)

    async def remove_claim(self, role: RoleT, claim: Claim) -> IdentityResult:
        """Removes a claim from a role.

        :param role: The role whose claim should be removed.
        :param claim: The claim to remove.
        :return: Returns the result of the operation.
        """
        if role is None:
            raise ArgumentNoneError("role")
        if claim is None:
            raise ArgumentNoneError("claim")

        await self._get_claim_store().remove_claim(role, claim)
        return await self._update_role(role)

    async def _validate_role(self, role: RoleT) -> IdentityResult:
        """Should return IdentityResult.Success if validation is successful.
        This is called before saving the role via create or update.

        :param role: The role to validate.
        :return: Returns the result of the operation.
        """
        if self.role_validators:
            errors: list[IdentityError] = []

            for rv in self.role_validators:
                result = await rv.validate(self, role)
                if not result.succeeded:
                    errors.extend(result.errors)

            if errors:
                self.logger.warning("Role validation failed: %s.", ", ".join(e.code for e in errors))
                return IdentityResult.failed(*errors)

        return IdentityResult.success()

    def _normalize_key(self, key: str | None) -> str | None:
        """Gets a normalized representation of the specified key.

        :param key: Value to normalize.
        :return: Returns the normalized representation of the specified key.
        """
        return self.key_normalizer.normalize_name(key) if self.key_normalizer else key

    async def _update_role(self, role: RoleT) -> IdentityResult:
        """Called to update the role after validating and updating the normalized role name.

        :param role: The role whose normalized name needs to be updated.
        :return: Returns the result of the operation.
        """
        result = await self._validate_role(role)
        if not result.succeeded:
            return result
        await self.update_normalized_role_name(role)
        return await self.store.update(role)

    def _get_claim_store(self) -> IRoleClaimStore[RoleT]:
        if self.supports_role_claims:
            return cast(IRoleClaimStore[RoleT], self.store)
        raise NotSupportedError(Resources.StoreNotIRoleClaimStore)
