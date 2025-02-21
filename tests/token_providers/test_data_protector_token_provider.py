import pytest

from pydentity.encryption import AESDataProtector
from pydentity.token_providers import DataProtectorTokenProvider


@pytest.mark.asyncio
async def test_data_protector_token_provider(user_manager, user):
    provider = DataProtectorTokenProvider(AESDataProtector("secret"))
    assert await provider.can_generate_two_factor(user_manager, user) is False
    token = await provider.generate(user_manager, "totp", user)
    result = await provider.validate(user_manager, "totp", token, user)
    assert result is True
    result = await provider.validate(user_manager, "fake", token, user)
    assert result is False
