import pytest

from pydentity.token_providers import EmailTokenProvider, PhoneNumberTokenProvider, TotpSecurityStampBasedTokenProvider


@pytest.mark.asyncio
async def test_totp_security_stamp_based_token_provider(user_manager, user):
    provider = TotpSecurityStampBasedTokenProvider()
    with pytest.raises(NotImplementedError):
        await provider.can_generate_two_factor(user_manager, user)
    token = await provider.generate(user_manager, "TOTP", user)
    result = await provider.validate(user_manager, "TOTP", token, user)
    assert result is True
    result = await provider.validate(user_manager, "FakeTOTP", token, user)
    assert result is False


@pytest.mark.asyncio
async def test_email_token_provider(user_manager, user):
    provider = EmailTokenProvider()
    assert await provider.can_generate_two_factor(user_manager, user)
    token = await provider.generate(user_manager, "ConfirmEmail", user)
    result = await provider.validate(user_manager, "ConfirmEmail", token, user)
    assert result is True
    result = await provider.validate(user_manager, "FakeEmail", token, user)
    assert result is False


@pytest.mark.asyncio
async def test_phone_token_provider(user_manager, user):
    provider = PhoneNumberTokenProvider()
    assert await provider.can_generate_two_factor(user_manager, user)
    token = await provider.generate(user_manager, "ConfirmPhone", user)
    result = await provider.validate(user_manager, "ConfirmPhone", token, user)
    assert result is True
    result = await provider.validate(user_manager, "FakePhone", token, user)
    assert result is False
