import uuid

import pytest

from pydentity.rfc6238_authentication_service import generate_key
from tests.utils import future_from_result


@pytest.fixture
def user_manager(mocker):
    _manager = mocker.Mock()
    mocker.patch.object(_manager, "get_email", return_value=future_from_result("john@example.com"))
    mocker.patch.object(_manager, "get_username", return_value=future_from_result("john_username"))
    mocker.patch.object(_manager, "get_user_id", return_value=future_from_result(uuid.uuid4().hex))
    mocker.patch.object(_manager, "get_authenticator_key", return_value=future_from_result(generate_key()))
    mocker.patch.object(_manager, "get_security_stamp", return_value=future_from_result(uuid.uuid4().hex))
    mocker.patch.object(_manager, "create_security_token", return_value=future_from_result(uuid.uuid4().hex))
    mocker.patch.object(_manager, "get_phone_number", return_value=future_from_result("+1234567890"))
    mocker.patch.object(_manager, "is_phone_number_confirmed", return_value=future_from_result(True))
    mocker.patch.object(_manager, "is_email_confirmed", return_value=future_from_result(True))
    mocker.patch.object(_manager, "supports_user_security_stamp", return_value=True)
    return _manager


@pytest.fixture
def user(mocker):
    return mocker.Mock()
