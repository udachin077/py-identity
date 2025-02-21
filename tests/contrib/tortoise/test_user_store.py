from uuid import uuid4

import pytest
import pytest_asyncio
from tortoise.exceptions import IntegrityError

from pydentity.contrib.tortoise.models import IdentityRole, IdentityUser
from pydentity.contrib.tortoise.stores import UserStore
from pydentity.security.claims import Claim
from pydentity.user_login_info import UserLoginInfo


async def _find_by_email(email: str) -> IdentityUser | None:
    return await IdentityUser.get_or_none(normalized_email=email.upper())


@pytest_asyncio.fixture(scope="session")
async def user_store():
    return UserStore()


@pytest_asyncio.fixture(loop_scope="session", autouse=True)
async def create_default_user():
    user = IdentityUser(
        email="admin@email.com",
        username="admin",
        normalized_email="admin@email.com".upper(),
        normalized_username="admin".upper(),
    )
    await user.save()


@pytest_asyncio.fixture
async def create_roles():
    await IdentityRole.bulk_create(
        [
            IdentityRole(name="admin", normalized_name="ADMIN"),
            IdentityRole(name="user", normalized_name="USER"),
            IdentityRole(name="guest", normalized_name="GUEST"),
        ]
    )


@pytest.mark.asyncio
async def test_all(user_store):
    await IdentityUser(
        email="user@email.com",
        username="user",
        normalized_email="user@email.com".upper(),
        normalized_username="user".upper(),
    ).save()
    assert len(await user_store.all()) == 2


@pytest.mark.asyncio
async def test_create(user_store):
    user = IdentityUser(
        email="user@email.com",
        username="user",
        normalized_email="user@email.com".upper(),
        normalized_username="user".upper(),
    )
    result = await user_store.create(user)
    assert result.succeeded is True
    found = await _find_by_email("user@email.com")
    assert found is not None

    with pytest.raises(IntegrityError):
        _user = IdentityUser(
            email="admin@email.com",
            username="admin",
            normalized_email="admin@email.com".upper(),
            normalized_username="admin".upper(),
        )
        await user_store.create(_user)


@pytest.mark.asyncio
async def test_update(user_store):
    user = await _find_by_email("admin@email.com")
    user.username = "UpdatedUser"
    user.normalized_name = "UPDATEDUSER"
    assert user.concurrency_stamp is None
    result = await user_store.update(user)
    assert result.succeeded is True
    assert user.concurrency_stamp is not None


@pytest.mark.asyncio
async def test_delete(user_store):
    user = await _find_by_email("admin@email.com")
    result = await user_store.delete(user)
    assert result.succeeded is True
    user = await _find_by_email("admin@email.com")
    assert user is None


@pytest.mark.asyncio
async def test_find_by(user_store):
    user = await _find_by_email("admin@email.com")

    found = await user_store.find_by_id(user.id)
    assert found is not None and found.username == "admin"
    assert await user_store.find_by_id(str(uuid4())) is None

    found = await user_store.find_by_name(user.normalized_username)
    assert found is not None
    assert await user_store.find_by_name("UNDEFINED") is None

    found = await user_store.find_by_email(user.normalized_email)
    assert found is not None
    assert await user_store.find_by_email("UNDEFINED") is None


@pytest.mark.asyncio
async def test_user_roles(user_store, create_roles):
    user = await _find_by_email("admin@email.com")
    user_1 = IdentityUser(
        email="user@email.com",
        username="user",
        normalized_email="user@email.com".upper(),
        normalized_username="user".upper(),
    )
    await user_1.save()

    await user_store.add_to_role(user, "ADMIN")
    await user_store.add_to_role(user, "USER")
    await user_store.add_to_role(user_1, "USER")

    roles = await user_store.get_roles(user)
    assert "admin" in roles and "user" in roles

    users = await user_store.get_users_in_role("USER")
    assert len(users) == 2

    assert await user_store.is_in_role(user, "USER") is True
    assert await user_store.is_in_role(user, "GUEST") is False

    await user_store.remove_from_role(user, "USER")
    assert await user_store.is_in_role(user, "USER") is False


@pytest.mark.asyncio
async def test_user_logins(user_store):
    user = await _find_by_email("admin@email.com")

    await user_store.add_login(user, UserLoginInfo("Google", "Key"))
    await user_store.add_login(user, UserLoginInfo("Outlook", "Key"))

    _user = await user_store.find_by_login("Google", "Key")
    assert _user is not None
    _user = await user_store.find_by_login("Google", "Key_1")
    assert _user is None
    _user = await user_store.find_by_login("Inbox", "Key")
    assert _user is None

    logins = await user_store.get_logins(user)
    assert len(logins) == 2
    await user_store.remove_login(user, "Google", "Key")
    logins = await user_store.get_logins(user)
    assert len(logins) == 1
    await user_store.remove_login(user, "Outlook", "Key")
    logins = await user_store.get_logins(user)
    assert len(logins) == 0


@pytest.mark.asyncio
async def test_user_tokens(user_store):
    user = await _find_by_email("admin@email.com")
    value = str(uuid4())

    await user_store.set_token(user, "Application", "auth", value)

    token = await user_store.get_token(user, "Application", "auth")
    assert token == value

    await user_store.set_token(user, "Application", "auth", str(uuid4()))
    token = await user_store.get_token(user, "Application", "auth")
    assert token != value

    await user_store.remove_token(user, "Application", "auth")
    token = await user_store.get_token(user, "Application", "auth")
    assert token is None


@pytest.mark.asyncio
async def test_authenticator_key(user_store):
    user = await _find_by_email("admin@email.com")
    value = str(uuid4())

    await user_store.set_authenticator_key(user, value)
    key = await user_store.get_authenticator_key(user)
    assert value == key


@pytest.mark.asyncio
async def test_codes(user_store):
    user = await _find_by_email("admin@email.com")
    codes = ["JbuGcQqKeUMi", "qrZnbnHJEIfH", "HsWXCfJUjNNb", "OOTRTeOJNASC", "cqRNElOWDUrT"]

    await user_store.replace_codes(user, *codes)
    result = await user_store.redeem_code(user, "JbuGcQqKeUMi")
    assert result is True
    count = await user_store.count_codes(user)
    assert count == 4
    result = await user_store.redeem_code(user, "qrZnbnHJEIfH")
    assert result is True
    result = await user_store.redeem_code(user, "HsWXCfJUjNNb")
    assert result is True
    result = await user_store.redeem_code(user, "HsWXCfJUjNNb")
    assert result is False
    count = await user_store.count_codes(user)
    assert count == 2


@pytest.mark.asyncio
async def test_claims(user_store):
    user = await _find_by_email("admin@email.com")
    user_1 = IdentityUser(
        email="user@email.com",
        username="user",
        normalized_email="user@email.com".upper(),
        normalized_username="user".upper(),
    )
    await user_1.save()
    claim = Claim("locality", "London")

    await user_store.add_claims(
        user, Claim("name", user.username), Claim("email", user.email), Claim("nameidentifier", user.id), claim
    )

    await user_store.add_claims(user_1, claim)

    claims = await user_store.get_claims(user)
    assert len(claims) == 4

    await user_store.replace_claim(user, Claim("name", user.username), Claim("phone", "999999999"))
    claims = await user_store.get_claims(user)
    assert len(claims) == 4
    assert any([True for c in claims if c.type == "phone"])

    await user_store.remove_claims(user, Claim("phone", "999999999"))
    claims = await user_store.get_claims(user)
    assert len(claims) == 3

    users = await user_store.get_users_for_claim(claim)
    assert len(users) == 2


@pytest.mark.asyncio
async def test_get_personal_data(user_store):
    user = await _find_by_email("admin@email.com")
    personal_data = await user_store.get_personal_data(user)
    assert personal_data == {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "email_confirmed": user.email_confirmed,
        "phone_number": user.phone_number,
        "phone_number_confirmed": user.phone_number_confirmed,
        "two_factor_enabled": user.two_factor_enabled,
    }
