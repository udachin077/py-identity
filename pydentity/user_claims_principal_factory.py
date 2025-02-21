from __future__ import annotations

from typing import TYPE_CHECKING, Generic

from pydentity.abc.user_claims_principal_factory import IUserClaimsPrincipalFactory
from pydentity.exc import ArgumentNoneError
from pydentity.identity_constants import IdentityConstants
from pydentity.models import RoleT, UserT
from pydentity.security.claims import Claim, ClaimsIdentity, ClaimsPrincipal, ClaimTypes

if TYPE_CHECKING:
    from pydentity.identity_options import IdentityOptions
    from pydentity.role_manager import RoleManager
    from pydentity.user_manager import UserManager

__all__ = ["UserClaimsPrincipalFactory"]


class UserClaimsPrincipalFactory(IUserClaimsPrincipalFactory[UserT, RoleT], Generic[UserT, RoleT]):
    """Provides methods to create a claims principal for a given user."""

    __slots__ = ("options", "role_manager", "user_manager")

    def __init__(
        self, user_manager: UserManager[UserT], role_manager: RoleManager[RoleT], options: IdentityOptions
    ) -> None:
        self.user_manager = user_manager
        self.role_manager = role_manager
        self.options = options

    async def create(self, user: UserT) -> ClaimsPrincipal:
        if user is None:
            raise ArgumentNoneError("user")

        user_id = await self.user_manager.get_user_id(user=user)
        username = await self.user_manager.get_username(user=user)
        options = self.options.claims_identity

        identity = ClaimsIdentity(
            IdentityConstants.ApplicationScheme,
            [
                Claim(ClaimTypes.NameIdentifier, user_id),
                Claim(ClaimTypes.Name, username),
            ],
            name_claim_type=options.username_claim_type,
            role_claim_type=options.role_claim_type,
        )

        if self.user_manager.supports_user_email:
            if email := await self.user_manager.get_email(user):
                identity.add_claims([Claim(options.email_claim_type, email)])

        if self.user_manager.supports_user_security_stamp:
            if security := await self.user_manager.get_security_stamp(user):
                identity.add_claims([Claim(options.security_stamp_claim_type, security)])

        if self.user_manager.supports_user_claim:
            if claims := await self.user_manager.get_claims(user):
                identity.add_claims(claims)

        if self.user_manager.supports_user_role:
            roles = await self.user_manager.get_roles(user)

            for role_name in roles:
                identity.add_claims([Claim(options.role_claim_type, role_name)])
                if self.role_manager.supports_role_claims:
                    if role := await self.role_manager.find_by_name(role_name):
                        role_claims = await self.role_manager.get_claims(role)
                        identity.add_claims(role_claims)

        return ClaimsPrincipal([identity])
