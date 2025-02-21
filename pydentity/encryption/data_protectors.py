import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from pydentity.abc.data_protector import IDataProtector
from pydentity.utils import ensure_bytes

__all__ = ["AESDataProtector", "CamelliaDataProtector", "FernetDataProtector", "SM4DataProtector"]


def update_key(
    key: str | bytes,
    salt: str | bytes = b"pyidentity",
    algorithm: type[hashes.HashAlgorithm] = hashes.SHA256,
    key_size: int = 32,
    iterations: int = 720000,
) -> bytes:
    return PBKDF2HMAC(
        algorithm=algorithm(),
        length=key_size,
        salt=ensure_bytes(salt),
        iterations=iterations,
    ).derive(ensure_bytes(key))


class FernetDataProtector(IDataProtector):
    """Fernet encryption backend."""

    def __init__(self, key: str | bytes) -> None:
        """Constructs a Fernet encryption backend.

        :param key: The key to use.
        """
        self._fernet = Fernet(base64.urlsafe_b64encode(update_key(key)))

    def encrypt(self, plaintext: str | bytes) -> bytes:
        encrypted_data = self._fernet.encrypt(ensure_bytes(plaintext))
        return base64.b64encode(encrypted_data)

    def decrypt(self, ciphertext: str | bytes) -> bytes:
        return self._fernet.decrypt(base64.b64decode(ensure_bytes(ciphertext)))


class _CipherDataProtector(IDataProtector):
    algorithm: type[algorithms.AES | algorithms.AES128 | algorithms.AES256 | algorithms.Camellia | algorithms.SM4]
    key_size: int = 32

    def __init__(self, key: str | bytes, salt: bytes | str = b"pyidentity.cryptography") -> None:
        """Constructs a Cipher encryption backend.

        :param key: The key to use.
        :param salt: The salt to use.
        """
        hashed_key = update_key(key, salt, key_size=self.key_size)
        self._padding = padding.PKCS7(self.algorithm.block_size)
        self._cipher = Cipher(self.algorithm(ensure_bytes(hashed_key)), modes.CBC(hashed_key[:16]))

    def encrypt(self, plaintext: str | bytes) -> bytes:
        padder = self._padding.padder()
        encryptor = self._cipher.encryptor()
        plaintext = padder.update(ensure_bytes(plaintext)) + padder.finalize()
        encrypted = encryptor.update(plaintext) + encryptor.finalize()
        return base64.b64encode(encrypted)

    def decrypt(self, ciphertext: str | bytes) -> bytes:
        unpadder = self._padding.unpadder()
        decryptor = self._cipher.decryptor()
        decrypted = decryptor.update(base64.b64decode(ensure_bytes(ciphertext))) + decryptor.finalize()
        return unpadder.update(decrypted) + unpadder.finalize()


class AESDataProtector(_CipherDataProtector):
    """AES encryption backend."""

    algorithm = algorithms.AES


class CamelliaDataProtector(_CipherDataProtector):
    """Camelia encryption backend."""

    algorithm = algorithms.Camellia


class SM4DataProtector(_CipherDataProtector):
    """SM4 encryption backend."""

    algorithm = algorithms.SM4
    key_size = 16
