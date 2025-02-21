import pytest

from pydentity.validators import PasswordValidator


@pytest.fixture
def password_validator():
    return PasswordValidator()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "passwords,expected",
    [
        (["t=yFV%w$`AG:vNP;8q9~/2", 'p"9Vu-Hk}>n/M*NPfZYUsa', "Ad%x7aZC"], True),
        (["apnioxa8f114cy0s839ten", "W3$o90", "Gqz<u?+)`].<oLF.>"], False),
    ],
)
async def test_validate_with_default_options(password_validator, user_manager, passwords, expected):
    for password in passwords:
        result = await password_validator.validate(user_manager, password)
        assert result.succeeded is expected, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "passwords,expected",
    [
        (["i*5b8[Jq#2W'-e%;", "z_.j$*hN;'_1HO", "a]CQe+BuAFNj#i7t"], True),
        (["Mgn9L,U,XYo", "EVJ|*D_5dwfuV"], False),
    ],
)
async def test_validate_required_length(password_validator, user_manager, passwords, expected):
    user_manager.options.password.required_length = 14
    for password in passwords:
        result = await password_validator.validate(user_manager, password)
        assert result.succeeded is expected, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "passwords,expected",
    [
        (["N;92V[FPGgRn<Z?^", "a?mR!;6Au3VMw>kC", "tLJ8)MFkG[x2*3V6d>W}&:"], True),
        (["VN;92VabVN;92V", "R;AuVMw>kC", "tLJ)MFkG[x:"], False),
    ],
)
async def test_validate_required_unique_chars(password_validator, user_manager, passwords, expected):
    user_manager.options.password.required_unique_chars = 8
    for password in passwords:
        result = await password_validator.validate(user_manager, password)
        assert result.succeeded is expected, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize("password", ["BkcDHe)<#", "SHx&|L{VjCF>leYP", "Oj8zSZu[e[`7/[Q;"])
async def test_validate_not_required_digit(password_validator, user_manager, password):
    user_manager.options.password.required_digit = False
    result = await password_validator.validate(user_manager, password)
    assert result.succeeded is True, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize("password", ['t~;r|%`c?j3vq<*y"b{h8d', 'e]:~6+>.n*!^g-a"}0#<$b', "p>`iznfg6bqr)#93j%_&h7"])
async def test_validate_required_uppercase(password_validator, user_manager, password):
    user_manager.options.password.required_uppercase = False
    result = await password_validator.validate(user_manager, password)
    assert result.succeeded is True, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize("password", ["PC_VT7F9H=]3K>6+A<N8M~", "XE[9.B4NU;D83L={", "TLJ8)MFKG[x2*3V6D>W}&:"])
async def test_validate_required_lowercase(password_validator, user_manager, password):
    user_manager.options.password.required_lowercase = False
    result = await password_validator.validate(user_manager, password)
    assert result.succeeded is True, result.errors


@pytest.mark.asyncio
@pytest.mark.parametrize("password", ["RF6HwsoTzmB81q9e", "jbTg62GeyOw5UoB3", "vj789D3lw250eZAh"])
async def test_validate_required_lowercase(password_validator, user_manager, password):
    user_manager.options.password.required_non_alphanumeric = False
    result = await password_validator.validate(user_manager, password)
    assert result.succeeded is True, result.errors
