import pytest

from pydentity.validators import RoleValidator
from tests.models import MockRole


@pytest.fixture
def role_validator():
    return RoleValidator()


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [MockRole(name="manager"), MockRole(name="sysadmin")])
async def test_validate(role_manager, role_validator, role):
    result = await role_validator.validate(role_manager, role)
    assert result.succeeded is True, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [MockRole(name="admin"), MockRole(name="user")])
async def test_validate_fail(role_manager, role_validator, role):
    result = await role_validator.validate(role_manager, role)
    assert result.succeeded is False
