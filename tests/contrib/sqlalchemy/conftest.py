import pytest
import pytest_asyncio
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from pydentity.contrib.sqlalchemy.models import *
from pydentity.contrib.sqlalchemy.stores import RoleStore, UserStore


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


@pytest.fixture(scope="session")
def engine() -> AsyncEngine:
    return create_async_engine("sqlite+aiosqlite://", echo=True)


@pytest_asyncio.fixture(loop_scope="session", autouse=True)
async def initialize_tests(engine):
    async with engine.begin() as conn:
        await conn.run_sync(Model.metadata.create_all)
        yield
        await conn.execute(delete(IdentityUser))
        await conn.execute(delete(IdentityRole))


@pytest.fixture(scope="session")
def async_session_maker(engine):
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest_asyncio.fixture(loop_scope="function")
async def session(async_session_maker):
    async with async_session_maker() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
