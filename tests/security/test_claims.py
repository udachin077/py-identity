import pytest

from pydentity.security.claims import Claim, ClaimsIdentity, ClaimsPrincipal, ClaimTypes


@pytest.fixture
def identity() -> ClaimsIdentity:
    return ClaimsIdentity(
        authentication_type="Application.Auth",
        claims=(
            Claim(ClaimTypes.Name, "johndoe"),
            Claim(ClaimTypes.Email, "johndoe@example.com"),
            Claim(ClaimTypes.Role, "admin"),
            Claim(ClaimTypes.Role, "chief"),
            Claim(ClaimTypes.Locality, "Paris"),
        ),
    )


@pytest.fixture
def principal(identity: ClaimsIdentity):
    additional_identity = ClaimsIdentity(
        claims=(Claim(ClaimTypes.Locality, "London"), Claim("age", 22)),
    )
    return ClaimsPrincipal(identities=(identity, additional_identity))


@pytest.mark.parametrize(
    "claim_type_or_predicate,expected",
    [
        (ClaimTypes.Role, 2),
        (ClaimTypes.Name, 1),
        (ClaimTypes.AuthenticationMethod, 0),
        (lambda c: c.type == ClaimTypes.Role, 2),
        (lambda c: c.type == ClaimTypes.Name, 1),
        (lambda c: c.type == ClaimTypes.AuthenticationMethod, 0),
    ],
)
def test_claims_identity_find_all(identity, claim_type_or_predicate, expected):
    assert len(list(identity.find_all(claim_type_or_predicate))) == expected


@pytest.mark.parametrize(
    "claim_type_or_predicate,expected",
    [
        (ClaimTypes.Role, True),
        (ClaimTypes.Name, True),
        (ClaimTypes.AuthenticationMethod, False),
        (lambda c: c.type == ClaimTypes.Name, True),
        (lambda c: c.type == ClaimTypes.AuthenticationMethod, False),
    ],
)
def test_claims_identity_find_first(identity, claim_type_or_predicate, expected):
    assert bool(identity.find_first(claim_type_or_predicate)) is expected


@pytest.mark.parametrize(
    "claim_type_or_predicate,expected",
    [
        (ClaimTypes.Role, ("admin", "chief")),
        (ClaimTypes.Name, ("johndoe",)),
        (ClaimTypes.AuthenticationMethod, (None,)),
        (lambda c: c.type == ClaimTypes.Name, ("johndoe",)),
        (lambda c: c.type == ClaimTypes.AuthenticationMethod, (None,)),
    ],
)
def test_claims_identity_find_first_value(identity, claim_type_or_predicate, expected):
    assert identity.find_first_value(claim_type_or_predicate) in expected


@pytest.mark.parametrize(
    "claim_type_or_predicate,claim_value,expected",
    [
        ("age", 22, False),
        (ClaimTypes.Role, "admin", True),
        (ClaimTypes.Name, "johndoe", True),
        (ClaimTypes.AuthenticationMethod, "amr", False),
        (lambda c: c.type == ClaimTypes.Name, None, True),
        (lambda c: c.type == ClaimTypes.AuthenticationMethod, None, False),
    ],
)
def test_claims_identity_has_claim(identity, claim_type_or_predicate, claim_value, expected):
    assert identity.has_claim(claim_type_or_predicate, claim_value) is expected


@pytest.mark.parametrize(
    "claim_type_or_predicate,expected",
    [
        (ClaimTypes.Role, 2),
        (ClaimTypes.Name, 1),
        (ClaimTypes.AuthenticationMethod, 0),
        (ClaimTypes.Locality, 2),
        (lambda c: c.type == ClaimTypes.Role, 2),
        (lambda c: c.type == ClaimTypes.Name, 1),
        (lambda c: c.type == ClaimTypes.AuthenticationMethod, 0),
        (lambda c: c.type == ClaimTypes.Locality, 2),
    ],
)
def test_claims_principal_find_all(principal, claim_type_or_predicate, expected):
    assert len(list(principal.find_all(claim_type_or_predicate))) == expected


@pytest.mark.parametrize(
    "claim_type_or_predicate,expected",
    [
        (ClaimTypes.Role, True),
        (ClaimTypes.Name, True),
        (ClaimTypes.AuthenticationMethod, False),
        (lambda c: c.type == ClaimTypes.Name, True),
        (lambda c: c.type == ClaimTypes.AuthenticationMethod, False),
    ],
)
def test_claims_principal_find_first(principal, claim_type_or_predicate, expected):
    assert bool(principal.find_first(claim_type_or_predicate)) is expected


@pytest.mark.parametrize(
    "claim_type_or_predicate,expected",
    [
        (ClaimTypes.Role, ["admin", "chief"]),
        (ClaimTypes.Name, ["johndoe"]),
        (ClaimTypes.AuthenticationMethod, [None]),
        (lambda c: c.type == ClaimTypes.Name, ["johndoe"]),
        (lambda c: c.type == ClaimTypes.AuthenticationMethod, [None]),
    ],
)
def test_claims_principal_find_first_value(principal, claim_type_or_predicate, expected):
    assert principal.find_first_value(claim_type_or_predicate) in expected


@pytest.mark.parametrize(
    "claim_type_or_predicate,claim_value,expected",
    [
        ("age", 22, True),
        (ClaimTypes.Locality, "London", True),
        (ClaimTypes.AuthenticationMethod, "amr", False),
        (lambda c: c.type == ClaimTypes.Name, None, True),
        (lambda c: c.type == ClaimTypes.AuthenticationMethod, None, False),
    ],
)
def test_claims_principal_has_claim(principal, claim_type_or_predicate, claim_value, expected):
    assert principal.has_claim(claim_type_or_predicate, claim_value) is expected


@pytest.mark.parametrize(
    "role,expected",
    [
        ("admin", True),
        ("chief", True),
        ("user", False),
    ],
)
def test_claims_principal_is_in_role(principal, role, expected):
    assert principal.is_in_role(role) is expected


@pytest.mark.parametrize(
    "roles,expected_any,expected_all",
    [
        (["admin", "chief"], True, True),
        (["admin", "user"], True, False),
        (["user", "manager"], False, False),
    ],
)
def test_claims_principal_is_in_roles(principal, roles, expected_any, expected_all):
    assert principal.is_in_roles(*roles, mode="any") is expected_any
    assert principal.is_in_roles(*roles, mode="all") is expected_all


def test_model_dump_load(principal):
    model = principal.model_dump()
    new_principal = ClaimsPrincipal.model_load(model)
    assert len(list(new_principal.identities)) == len(list(principal.identities))
    assert len(list(principal.claims)) == len(list(new_principal.claims))
    assert new_principal.identity.is_authenticated is principal.identity.is_authenticated
    assert new_principal.identity.authentication_type == principal.identity.authentication_type
