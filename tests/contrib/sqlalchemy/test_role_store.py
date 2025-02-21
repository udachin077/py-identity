from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, InvalidRequestError

from pydentity.contrib.sqlalchemy.models import IdentityRole
from pydentity.contrib.sqlalchemy.stores import RoleStore
from pydentity.security.claims import Claim


@pytest_asyncio.fixture(loop_scope="function")
async def role_store(session):
    return RoleStore(session)


@pytest.mark.asyncio
async def test_all(role_store, session):
    session.add_all(
        [
            IdentityRole(name="admin", normalized_name="ADMIN"),
            IdentityRole(name="user", normalized_name="USER"),
            IdentityRole(name="guest", normalized_name="GUEST"),
        ]
    )
    await session.commit()
    assert len(await role_store.all()) == 3


@pytest.mark.asyncio
async def test_create(role_store, session):
    role = IdentityRole(name="test_create", normalized_name="test_create".upper())
    result = await role_store.create(role)
    assert result.succeeded is True
    found = await session.execute(
        select(IdentityRole).where(IdentityRole.normalized_name == "test_create".upper())  # type: ignore
    )
    assert len(found.all()) == 1

    with pytest.raises(IntegrityError):
        role = IdentityRole(name="test_create", normalized_name="test_create".upper())
        await role_store.create(role)


@pytest.mark.asyncio
async def test_update(role_store, session):
    session.add(IdentityRole(name="test_update", normalized_name="test_update".upper()))
    await session.commit()
    found = await session.execute(
        select(IdentityRole).where(IdentityRole.normalized_name == "test_update".upper())  # type: ignore
    )
    role: IdentityRole = found.scalar_one_or_none()

    role.name = "UpdatedRole"
    role.normalized_name = "UPDATEDROLE"
    assert role.concurrency_stamp is None
    result = await role_store.update(role)
    assert result.succeeded is True
    assert role.concurrency_stamp is not None
    found = await session.execute(
        select(IdentityRole).where(IdentityRole.normalized_name == "UPDATEDROLE")  # type: ignore
    )
    role: IdentityRole = found.scalar_one_or_none()
    assert role


@pytest.mark.asyncio
async def test_delete(role_store, session):
    session.add(IdentityRole(name="test_delete", normalized_name="test_delete".upper()))
    await session.commit()
    found = await session.execute(
        select(IdentityRole).where(IdentityRole.normalized_name == "test_delete".upper())  # type: ignore
    )
    role: IdentityRole = found.scalar_one_or_none()

    result = await role_store.delete(role)
    assert result.succeeded is True
    re_found = await session.execute(
        select(IdentityRole).where(IdentityRole.normalized_name == "test_delete".upper())  # type: ignore
    )
    assert re_found.scalar_one_or_none() is None

    with pytest.raises(InvalidRequestError):
        await role_store.delete(IdentityRole(name="test_delete_1", normalized_name="test_delete_1".upper()))


@pytest.mark.asyncio
async def test_find_by_id(role_store, session):
    role = IdentityRole(name="test_find_by_id", normalized_name="test_find_by_id".upper())
    session.add(role)
    await session.commit()

    found = await role_store.find_by_id(role.id)
    assert found is not None and found.name == "test_find_by_id"
    assert await role_store.find_by_id(str(uuid4())) is None


@pytest.mark.asyncio
async def test_find_by_name(role_store, session):
    role = IdentityRole(name="test_find_by_name", normalized_name="test_find_by_name".upper())
    session.add(role)
    await session.commit()

    found = await role_store.find_by_name("test_find_by_name".upper())
    assert found is not None
    assert await role_store.find_by_name("UNDEFINED") is None


@pytest.mark.asyncio
async def test_claim(role_store, session):
    role = IdentityRole(name="test_claim", normalized_name="test_claim".upper())
    session.add(role)
    await session.commit()

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
