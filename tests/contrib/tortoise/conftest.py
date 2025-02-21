import asyncio

import pytest
import pytest_asyncio
from tortoise import Tortoise

from pydentity.contrib.tortoise.models import (
    IdentityRole,
    IdentityRoleClaim,
    IdentityUser,
    IdentityUserClaim,
    IdentityUserLogin,
    IdentityUserRole,
    IdentityUserToken,
)
from pydentity.contrib.tortoise.stores import RoleStore, UserStore


@pytest.fixture(scope="session", autouse=True)
def event_loop():
    """Force the pytest-asyncio loop to be the main one."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session", autouse=True)
def set_user_models():
    UserStore.users = IdentityUser
    UserStore.user_roles = IdentityUserRole
    UserStore.user_claims = IdentityUserClaim
    UserStore.user_logins = IdentityUserLogin
    UserStore.user_tokens = IdentityUserToken
    UserStore.roles = IdentityRole


@pytest.fixture(scope="session", autouse=True)
def set_role_models():
    RoleStore.roles = IdentityRole
    RoleStore.role_claims = IdentityRoleClaim


@pytest_asyncio.fixture(scope="session", autouse=True)
async def initialize_tests():
    await Tortoise.init(
        db_url="sqlite://:memory:",
        modules={"models": ["pydentity.contrib.tortoise.models"]},
    )
    await Tortoise.generate_schemas()
    yield
    await Tortoise.close_connections()


@pytest_asyncio.fixture(scope="function", autouse=True)
async def clear():
    yield
    await IdentityUser.all().delete()
    await IdentityRole.all().delete()
