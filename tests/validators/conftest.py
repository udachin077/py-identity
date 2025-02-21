import pytest

from pydentity import IdentityOptions
from tests.models import MockRole, MockUser

MOCK_DB = {
    "Roles": [MockRole(name="admin"), MockRole(name="user")],
    "Users": [
        MockUser(email="alex@example.com", username="alex"),
        MockUser(email="john@example.com", username="john"),
        MockUser(email="sam@example.com", username="sam"),
    ],
}


async def get_email(user):
    return user.email


async def get_username(user):
    return user.username


async def get_user_id(user):
    return user.id


async def find_by_email(normalized_email):
    for item in MOCK_DB["Users"]:
        if item.normalized_email == normalized_email.upper():
            return item
    return None


def find_by_name(db):
    async def _wrapper(normalized_name):
        for item in MOCK_DB[db]:
            name = item.normalized_name if db == "Roles" else item.normalized_username
            if name == normalized_name.upper():
                return item
        return None

    return _wrapper


async def get_role_name(role):
    return role.name


async def get_role_id(role):
    return role.id


@pytest.fixture
def user_manager(mocker):
    _manager = mocker.Mock()
    _manager.options = IdentityOptions()
    mocker.patch.object(_manager, "get_email", side_effect=get_email)
    mocker.patch.object(_manager, "get_username", side_effect=get_username)
    mocker.patch.object(_manager, "get_user_id", side_effect=get_user_id)
    mocker.patch.object(_manager, "find_by_name", side_effect=find_by_name("Users"))
    mocker.patch.object(_manager, "find_by_email", side_effect=find_by_email)
    return _manager


@pytest.fixture
def role_manager(mocker):
    _manager = mocker.Mock()
    mocker.patch.object(_manager, "get_role_name", side_effect=get_role_name)
    mocker.patch.object(_manager, "get_role_id", side_effect=get_role_id)
    mocker.patch.object(_manager, "find_by_name", side_effect=find_by_name("Roles"))
    return _manager
