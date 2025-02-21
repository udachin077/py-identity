from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any, Literal, Self, overload

from pydentity.exc import InvalidOperationError

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable

__all__ = ["Claim", "ClaimTypes", "ClaimsIdentity", "ClaimsPrincipal"]

_DEFAULT_ISSUER = "LOCAL AUTHORITY"
_UNDEFINED_AUTHENTICATION_TYPE = "Undefined"


class ClaimTypes:
    AuthenticationInstant = "authenticationinstant"
    AuthenticationMethod = "authenticationmethod"
    CookiePath = "cookiepath"
    DenyOnlyPrimarySid = "denyonlyprimarysid"
    DenyOnlyPrimaryGroupSid = "denyonlyprimarygroupsid"
    DenyOnlyWindowsDeviceGroup = "denyonlywindowsdevicegroup"
    Dsa = "dsa"
    Expiration = "expiration"
    Expired = "expired"
    GroupSid = "groupsid"
    IsPersistent = "ispersistent"
    PrimaryGroupSid = "primarygroupsid"
    PrimarySid = "primarysid"
    Role = "role"
    SecurityStamp = "securitystamp"
    SerialNumber = "serialnumber"
    UserData = "userdata"
    Version = "version"
    WindowsAccountName = "windowsaccountname"
    WindowsDeviceClaim = "windowsdeviceclaim"
    WindowsDeviceGroup = "windowsdevicegroup"
    WindowsUserClaim = "windowsuserclaim"
    WindowsFqbnVersion = "windowsfqbnversion"
    WindowsSubAuthority = "windowssubauthority"
    Anonymous = "anonymous"
    Authentication = "authentication"
    AuthorizationDecision = "authorizationdecision"
    Country = "country"
    DateOfBirth = "dateofbirth"
    Dns = "dns"
    DenyOnlySid = "denyonlysid"
    Email = "emailaddress"
    Gender = "gender"
    GivenName = "givenname"
    Hash = "hash"
    HomePhone = "homephone"
    Locality = "locality"
    MobilePhone = "mobilephone"
    Name = "name"
    NameIdentifier = "nameidentifier"
    OtherPhone = "otherphone"
    PostalCode = "postalcode"
    Rsa = "rsa"
    Sid = "sid"
    Spn = "spn"
    StateOrProvince = "stateorprovince"
    StreetAddress = "streetaddress"
    Surname = "surname"
    System = "system"
    Thumbprint = "thumbprint"
    Upn = "upn"
    Uri = "uri"
    Webpage = "webpage"
    X500DistinguishedName = "x500distinguishedname"
    Actor = "actor"


class Claim:
    __slots__ = ("issuer", "original_issuer", "subject", "type", "value")

    def __init__(
        self,
        type: str,
        value: Any,
        issuer: str = _DEFAULT_ISSUER,
        original_issuer: str | None = None,
        subject: ClaimsIdentity | None = None,
    ) -> None:
        self.type = type
        self.value = value
        self.issuer = issuer
        self.original_issuer = original_issuer or issuer
        self.subject = subject

    def clone(self, identity: ClaimsIdentity) -> Self:
        return self.__class__(
            type=self.type,
            value=self.value,
            issuer=self.issuer,
            original_issuer=self.original_issuer,
            subject=identity,
        )

    def model_dump(self) -> dict[str, Any]:
        dump = {"type": self.type, "value": self.value}
        if self.issuer != _DEFAULT_ISSUER:
            dump.update({"issuer": self.issuer})
        if self.original_issuer != _DEFAULT_ISSUER:
            dump.update({"original_issuer": self.original_issuer})
        return dump


class ClaimsIdentity:
    __slots__ = ("_claims", "authentication_type", "name_claim_type", "role_claim_type")

    def __init__(
        self,
        authentication_type: str | None = None,
        claims: Iterable[Claim] = (),
        name_claim_type: str | None = None,
        role_claim_type: str | None = None,
    ):
        self.authentication_type = authentication_type
        self.name_claim_type = name_claim_type or ClaimTypes.Name
        self.role_claim_type = role_claim_type or ClaimTypes.Role
        self._claims: set[Claim] = set()
        self.add_claims(claims)

    @property
    def name(self) -> str | None:
        """Gets the name of the claim."""
        return self.find_first_value(self.name_claim_type)

    @property
    def is_authenticated(self) -> bool:
        """Checks if the claim is authenticated."""
        return bool(self.authentication_type)

    @property
    def claims(self) -> Generator[Claim]:
        """*Claims* for identity."""
        yield from self._claims

    def add_claims(self, claims: Iterable[Claim]) -> None:
        """Adds *claims* to the claims identity."""
        for claim in claims:
            if claim.subject is self:
                self._claims.add(claim)
            else:
                self._claims.add(claim.clone(self))

    def remove_claims(self, *claims: Claim) -> None:
        """Removes *claims* from the claims identity."""
        for claim in claims:
            self._claims.remove(claim)

    @overload
    def find_all(self, predicate: Callable[[Claim], bool], /) -> Generator[Claim]: ...

    @overload
    def find_all(self, claim_type: str, /) -> Generator[Claim]: ...

    def find_all(self, claim_type_or_predicate: str | Callable[[Claim], bool]) -> Generator[Claim]:
        """Retrieves a *Claims* where each *claim_type_or_predicate* equals Claim.type or predicate.

        :param claim_type_or_predicate: The type of the claim to match or predicate.
        :return:
        """
        if callable(claim_type_or_predicate):
            yield from filter(claim_type_or_predicate, self._claims)
            return
        if isinstance(claim_type_or_predicate, str):
            yield from filter(lambda c: c.type == claim_type_or_predicate, self._claims)
            return
        raise ValueError("'claim_type_or_predicate' must be 'str' or 'Callable[[Claim], bool]'")

    @overload
    def find_first(self, predicate: Callable[[Claim], bool], /) -> Claim | None: ...

    @overload
    def find_first(self, claim_type: str, /) -> Claim | None: ...

    def find_first(self, claim_type_or_predicate: str | Callable[[Claim], bool]) -> Claim | None:
        """Retrieves the first *Claims* that match matches.

        :param claim_type_or_predicate: The type of the claim to match or predicate.
        :return:
        """
        return _find_first(self.claims, claim_type_or_predicate)

    @overload
    def find_first_value(self, predicate: Callable[[Claim], bool], /) -> Any | None: ...

    @overload
    def find_first_value(self, claim_type: str, /) -> Any | None: ...

    def find_first_value(self, claim_type_or_predicate: str | Callable[[Claim], bool]) -> Any | None:
        """Return the claim value for the first claim with the specified *claim_type* or *predicate* if it exists,
        None otherwise.

        :param claim_type_or_predicate: The type of the claim to match or predicate.
        :return:
        """
        return _find_first_value(self._claims, claim_type_or_predicate)

    @overload
    def has_claim(self, predicate: Callable[[Claim], bool], /) -> bool: ...

    @overload
    def has_claim(self, claim_type: str, claim_value: Any, /) -> bool: ...

    def has_claim(self, claim_type_or_predicate: str | Callable[[Claim], bool], claim_value: Any = None) -> bool:
        """Determines if a claim of *claim_type* AND *claim_value* or *predicate* exists in any of the identities.

        :param claim_type_or_predicate: The type of the claim to match or predicate.
        :param claim_value: The value of the claim to match.
        :return:
        """
        return _has_claim(self.claims, claim_type_or_predicate, claim_value)

    def model_dump(self) -> dict[str, Any]:
        dump = {
            "authentication_type": self.authentication_type,
            "claims": [claim.model_dump() for claim in self._claims],
        }
        if self.name_claim_type != ClaimTypes.Name:
            dump["name_claim_type"] = self.name_claim_type
        if self.role_claim_type != ClaimTypes.Role:
            dump["role_claim_type"] = self.role_claim_type
        return dump

    @classmethod
    def model_load(cls, data: dict[str, Any]) -> Self:
        return cls(
            claims=(Claim(**claim) for claim in data.get("claims", ())),
            name_claim_type=data.get("name_claim_type"),
            role_claim_type=data.get("role_claim_type"),
        )


SelectPrimaryIdentity = Callable[[Sequence[ClaimsIdentity]], ClaimsIdentity | None]


def _select_primary_identity(identities: Sequence[ClaimsIdentity]) -> ClaimsIdentity | None:
    for identity in identities:
        if identity.is_authenticated:
            return identity
    try:
        return identities[0]
    except IndexError:
        return None


class ClaimsPrincipal:
    select_primary_identity: SelectPrimaryIdentity = _select_primary_identity

    __slots__ = ("_identities",)

    def __init__(self, identities: Iterable[ClaimsIdentity] | None = None):
        self._identities: list[ClaimsIdentity] = []
        self.add_identities(identities or ())

    @property
    def identities(self) -> Generator[ClaimsIdentity]:
        yield from self._identities

    @property
    def identity(self) -> ClaimsIdentity | None:
        return self.__class__.select_primary_identity(self._identities)

    @property
    def claims(self) -> Generator[Claim]:
        for identity in self._identities:
            yield from identity.claims

    def add_identities(self, identities: Iterable[ClaimsIdentity]) -> None:
        """Adds *ClaimsIdentity* to the internal list.

        :param identities:
        :return:
        """
        self._identities.extend(identities)

    @overload
    def find_all(self, predicate: Callable[[Claim], bool], /) -> Generator[Claim]: ...

    @overload
    def find_all(self, claim_type: str, /) -> Generator[Claim]: ...

    def find_all(self, claim_type_or_predicate: str | Callable[[Claim], bool]) -> Generator[Claim]:
        """Retrieves a *Claims* where each *claim_type_or_predicate* equals Claim.type or predicate.

        :param claim_type_or_predicate: The type of the claim to match or predicate.
        :return:
        """
        if callable(claim_type_or_predicate):
            yield from filter(claim_type_or_predicate, self.claims)
            return
        if isinstance(claim_type_or_predicate, str):
            yield from filter(lambda c: c.type == claim_type_or_predicate, self.claims)
            return
        raise ValueError("'claim_type_or_predicate' must be 'str' or 'Callable[[Claim], bool]'")

    @overload
    def find_first(self, predicate: Callable[[Claim], bool], /) -> Claim | None: ...

    @overload
    def find_first(self, claim_type: str, /) -> Claim | None: ...

    def find_first(self, claim_type_or_predicate: str | Callable[[Claim], bool]) -> Claim | None:
        """Retrieves the first *Claims* that match matches.

        :param claim_type_or_predicate: The type of the claim to match or predicate.
        :return:
        """
        return _find_first(self.claims, claim_type_or_predicate)

    @overload
    def find_first_value(self, predicate: Callable[[Claim], bool], /) -> Any | None: ...

    @overload
    def find_first_value(self, claim_type: str, /) -> Any | None: ...

    def find_first_value(self, claim_type_or_predicate: str | Callable[[Claim], bool]) -> Any | None:
        """Return the claim value for the first claim with the specified *claim_type* or *predicate* if it exists,
        None otherwise.

        :param claim_type_or_predicate: The type of the claim to match or predicate.
        :return:
        """
        return _find_first_value(self.claims, claim_type_or_predicate)

    @overload
    def has_claim(self, predicate: Callable[[Claim], bool], /) -> bool: ...

    @overload
    def has_claim(self, claim_type: str, claim_value: Any, /) -> bool: ...

    def has_claim(self, claim_type_or_predicate: str | Callable[[Claim], bool], claim_value: Any = None) -> bool:
        """Determines if a claim of *claim_type* AND *claim_value* or *predicate* exists in any of the identities.

        :param claim_type_or_predicate: The type of the claim to match or predicate.
        :param claim_value: The value of the claim to match.
        :return:
        """
        return _has_claim(self.claims, claim_type_or_predicate, claim_value)

    def is_in_role(self, role: str) -> bool:
        """*is_in_role* answers the question: does an builders this principal possesses
        contains a claim of type *role_claim_type* where the value is "==" to the role.

        :param role: The role to check for.
        :return:
        """
        return bool(any(identity.has_claim(identity.role_claim_type, role) for identity in self._identities))

    def is_in_roles(self, *roles: str, mode: Literal["all", "any"] = "any") -> bool:
        """*is_in_role* answers the question: does an builders this principal possesses
        contains a claim of type *role_claim_type* where the value is "==" to the roles.

        :param roles: The roles to check for.
        :param mode: Verification mode. Default is *any*.
        :return:
        """
        if not roles:
            raise ValueError("'roles' cannot be empty")
        if mode == "any":
            return any(True for role in roles if self.is_in_role(role))
        if mode == "all":
            return all(False for role in roles if not self.is_in_role(role))
        raise ValueError("The 'mode' must be 'all' or 'any'")

    def model_dump(self) -> dict[str, Any]:
        dump = defaultdict(list)
        for identity in self._identities:
            identity_dump = identity.model_dump()
            auth_type = identity_dump.pop("authentication_type") or _UNDEFINED_AUTHENTICATION_TYPE
            dump[auth_type].append(identity_dump)
        return dump

    @classmethod
    def model_load(cls, data: dict[str, Any]) -> Self:
        identities = []
        for auth_type, identity_dumps in data.items():
            for identity_dump in identity_dumps:
                identity = ClaimsIdentity.model_load(identity_dump)
                identity.authentication_type = auth_type if auth_type != _UNDEFINED_AUTHENTICATION_TYPE else None
                identities.append(identity)
        return cls(identities)


def _find_first(claims: Iterable[Claim], claim_type_or_predicate: str | Callable[[Claim], bool]) -> Claim | None:
    if callable(claim_type_or_predicate):
        predicate = claim_type_or_predicate
    elif isinstance(claim_type_or_predicate, str):

        def predicate(c: Claim) -> bool:
            return c.type == claim_type_or_predicate
    else:
        raise TypeError("'claim_type_or_predicate' must be 'str' or 'Callable[[Claim], bool]'")

    for claim in claims:
        if predicate(claim):
            return claim
    return None


def _find_first_value(claims: Iterable[Claim], claim_type_or_predicate: str | Callable[[Claim], bool]) -> Any | None:
    claim = _find_first(claims, claim_type_or_predicate)
    return claim.value if claim is not None else None


def _has_claim(claims: Iterable[Claim], *args: str | Callable[[Claim], bool] | Any) -> bool:
    len_args, arg0 = len(args), args[0]
    if callable(arg0):
        return bool(_find_first(claims, arg0))
    if len_args == 2 and isinstance(arg0, str):
        return bool(_find_first(claims, lambda c: c.type == arg0 and c.value == args[1]))
    raise InvalidOperationError("'args' can contain only 1 ('Callable[[Claim], bool]') or 2 ('str', 'Any') parameters.")
