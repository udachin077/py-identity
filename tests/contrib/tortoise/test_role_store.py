from uuid import uuid4

import pytest
import pytest_asyncio
from tortoise.exceptions import IntegrityError

from pydentity.contrib.tortoise.models import IdentityRole
from pydentity.contrib.tortoise.stores import RoleStore
from pydentity.security.claims import Claim


@pytest_asyncio.fixture(scope="session")
async def role_store():
    return RoleStore()


@pytest.mark.asyncio
async def test_all(role_store):
    await IdentityRole.bulk_create(
        [
            IdentityRole(name="admin", normalized_name="ADMIN"),
            IdentityRole(name="user", normalized_name="USER"),
            IdentityRole(name="guest", normalized_name="GUEST"),
        ]
    )
    assert len(await role_store.all()) == 3


@pytest.mark.asyncio
async def test_create(role_store):
    role = IdentityRole(name="test_create", normalized_name="test_create".upper())
    result = await role_store.create(role)
    assert result.succeeded is True
    found = await IdentityRole.filter(normalized_name="test_create".upper())  # type: ignore
    assert len(found) == 1

    with pytest.raises(IntegrityError):
        role = IdentityRole(name="test_create", normalized_name="test_create".upper())
        await role_store.create(role)


@pytest.mark.asyncio
async def test_update(role_store):
    await IdentityRole(name="test_update", normalized_name="test_update".upper()).save()
    role: IdentityRole = await IdentityRole.get_or_none(normalized_name="test_update".upper())

    role.name = "UpdatedRole"
    role.normalized_name = "UPDATEDROLE"
    assert role.concurrency_stamp is None
    result = await role_store.update(role)
    assert result.succeeded is True
    assert role.concurrency_stamp is not None


@pytest.mark.asyncio
async def test_delete(role_store):
    role = IdentityRole(name="test_delete", normalized_name="test_delete".upper())
    await role.save()

    result = await role_store.delete(role)
    assert result.succeeded is True


@pytest.mark.asyncio
async def test_find_by_id(role_store):
    role = IdentityRole(name="test_find_by_id", normalized_name="test_find_by_id".upper())
    await role.save()

    found = await role_store.find_by_id(role.id)
    assert found is not None and found.name == "test_find_by_id"
    assert await role_store.find_by_id(str(uuid4())) is None


@pytest.mark.asyncio
async def test_find_by_name(role_store):
    role = IdentityRole(name="test_find_by_name", normalized_name="test_find_by_name".upper())
    await role.save()

    found = await role_store.find_by_name("test_find_by_name".upper())
    assert found is not None
    assert await role_store.find_by_name("UNDEFINED") is None


@pytest.mark.asyncio
async def test_claim(role_store):
    role = IdentityRole(name="test_claim", normalized_name="test_claim".upper())
    await role.save()

    await role_store.add_claim(role, Claim("Name", "test_claim"))
    await role_store.add_claim(role, Claim("Name", "test_claim"))
    await role_store.add_claim(role, Claim("Email", "test_claim@email.com"))

    claims = await role_store.get_claims(role)
    assert len(claims) == 3

    await role_store.remove_claim(role, Claim("Email", "test_claim@email.com"))
    claims = await role_store.get_claims(role)
    assert len(claims) == 2

    await role_store.remove_claim(role, Claim("Name", "test_claim"))
    claims = await role_store.get_claims(role)
    assert len(claims) == 0
