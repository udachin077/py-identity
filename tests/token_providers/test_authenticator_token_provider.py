import pytest

from pydentity.rfc6238_authentication_service import generate_code
from pydentity.token_providers import AuthenticatorTokenProvider


@pytest.mark.asyncio
async def test_authenticator_token_provider(user_manager, user):
    provider = AuthenticatorTokenProvider()
    assert await provider.can_generate_two_factor(user_manager, user) is True
    token = await provider.generate(user_manager, "", user)
    assert token == ""
    token = generate_code(await user_manager.get_authenticator_key(user))
    result = await provider.validate(user_manager, "", token, user)
    assert result is True
