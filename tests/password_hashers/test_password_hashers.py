from typing import cast

import pytest

from pydentity.exc import ArgumentNoneError
from pydentity.models import UserProtokol
from pydentity.password_hashers import (
    Argon2PasswordHasher,
    BcryptPasswordHasher,
    PasswordVerificationResult,
    PBKDF2PasswordHasher,
)

HASHERS = [BcryptPasswordHasher(), Argon2PasswordHasher(), PBKDF2PasswordHasher()]
PASSWORDS = ["s>(2-8C;gP5X?[pYU=aM@9", "jwNt;&d6SkTBvu_c-n]=LY", "Dw2Cr]c>~duV(:$B6zSFgW"]

# We use stubs, since user data is not used when hashing a password.
MOCK_USER = cast(object(), UserProtokol)


@pytest.mark.parametrize("hasher", HASHERS)
@pytest.mark.parametrize("password", PASSWORDS)
def test_password_hasher(hasher, password):
    pwd_hash = hasher.hash_password(MOCK_USER, password)
    assert password != pwd_hash
    result = hasher.verify_hashed_password(MOCK_USER, pwd_hash, password)
    assert result == PasswordVerificationResult.Success


@pytest.mark.parametrize("hasher", HASHERS)
@pytest.mark.parametrize("password", PASSWORDS)
def test_password_hasher_failed(hasher, password):
    pwd_hash = hasher.hash_password(MOCK_USER, "P@ssW0rd")
    assert password != pwd_hash
    result = hasher.verify_hashed_password(MOCK_USER, pwd_hash, password)
    assert result == PasswordVerificationResult.Failed


@pytest.mark.parametrize("hasher", HASHERS)
def test_password_hasher_error(hasher):
    with pytest.raises(ArgumentNoneError):
        hasher.hash_password(MOCK_USER, None)
