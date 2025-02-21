import os

import pytest
from cryptography.fernet import Fernet

from pydentity.encryption import (
    AESDataProtector,
    CamelliaDataProtector,
    FernetDataProtector,
    PersonalDataProtector,
    SM4DataProtector,
)

DATA_PROTECTORS = [
    FernetDataProtector(Fernet.generate_key()),
    AESDataProtector(os.urandom(32)),
    CamelliaDataProtector(os.urandom(32)),
    SM4DataProtector(os.urandom(16)),
]
PERSONAL_DATA = ["alex@example.com", b"personal data"]


@pytest.mark.parametrize("protector", DATA_PROTECTORS)
def test_encrypt_decrypt(protector):
    encrypted_data = protector.encrypt("any_secret_string")
    decrypted_data = protector.decrypt(encrypted_data)
    assert decrypted_data.decode("utf-8") == "any_secret_string"


@pytest.mark.parametrize("data", PERSONAL_DATA)
@pytest.mark.parametrize("protector", [*DATA_PROTECTORS, "secret"])
def test_personal_data_protector(protector, data):
    personal_protector = PersonalDataProtector(protector)
    protected_data = personal_protector.protect("any_secret_string")
    unprotected_data = personal_protector.unprotect(protected_data)
    assert unprotected_data == "any_secret_string"


@pytest.mark.parametrize("data", PERSONAL_DATA)
@pytest.mark.parametrize("protector", [*DATA_PROTECTORS, "secret"])
def test_personal_data_protector_raise(protector, data):
    personal_protector = PersonalDataProtector(protector)
    protected_data = personal_protector.protect(data)
    invalid_protector = PersonalDataProtector(AESDataProtector("invalid_key"))
    with pytest.raises(ValueError):
        invalid_protector.unprotect(protected_data)
