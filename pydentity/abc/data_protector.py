from abc import ABC, abstractmethod

__all__ = ["IDataProtector", "IPersonalDataProtector"]


class IDataProtector(ABC):
    """Provides an abstraction used for data encryption."""

    @abstractmethod
    def encrypt(self, plaintext: str | bytes) -> bytes:
        """Encrypts the given plaintext.

        :param plaintext: Text or bytes to be encrypted.
        :return: Encrypted bytes.
        """

    @abstractmethod
    def decrypt(self, ciphertext: str | bytes) -> bytes:
        """Decrypts the given ciphertext.

        :param ciphertext: Encrypted data to be decrypted.
        :return: Decrypted bytes.
        """


class IPersonalDataProtector(ABC):
    """Provides an abstraction used for personal data encryption."""

    @abstractmethod
    def protect(self, data: str | bytes) -> str:
        """Protect the data.

        :param data: The data to protect.
        :return: The protected data.
        """

    @abstractmethod
    def unprotect(self, data: str | bytes) -> str:
        """Unprotect the data.

        :param data: The data to unprotect.
        :return: The unprotected data.
        """
