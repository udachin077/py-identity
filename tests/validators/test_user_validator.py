import pytest

from pydentity.validators import UserValidator
from tests.models import MockUser


@pytest.fixture
def user_validator():
    return UserValidator()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "user",
    [
        MockUser(email="anna@email.com", username="anna"),
        MockUser(email="ella@email.com", username="ella"),
    ],
)
async def test_validate(user_manager, user_validator, user):
    result = await user_validator.validate(user_manager, user)
    assert result.succeeded is True, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "user",
    [
        MockUser(email="john@example.com", username="john"),
        MockUser(email="john@example.com", username="new_username"),
        MockUser(email="new_email@example.com", username="john"),
        MockUser(email="invalid_email", username="john"),
    ],
)
async def test_validate_fail(user_manager, user_validator, user):
    result = await user_validator.validate(user_manager, user)
    assert result.succeeded is False
