from typing import Any

import pyotp

__all__ = [
    "generate_code",
    "generate_key",
    "get_provisioning_uri",
    "validate_code",
]


class Rfc6238AuthenticationService:
    @staticmethod
    def generate_code(secret: str, digits: int = 6, digest: Any = None, interval: int = 30) -> str:
        """Generate the current time OTP.

        :param secret: Secret in base32 format.
        :param digits: Number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        :param digest: Digest function to use in the HMAC (expected to be SHA1)
        :param interval: The time interval in seconds for OTP. This defaults to 30.
        """
        return pyotp.TOTP(secret, digits=digits, digest=digest, interval=interval).now()

    @staticmethod
    def validate_code(secret: str, code: str, digits: int = 6, digest: Any = None, interval: int = 30) -> bool:
        """Verifies the OTP passed in against the current time OTP.

        :param secret: Secret in base32 format.
        :param code: The OTP to check against.
        :param digits: Number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        :param digest: Digest function to use in the HMAC (expected to be SHA1)
        :param interval: The time interval in seconds for OTP. This defaults to 30.
        """
        return pyotp.TOTP(secret, digits=digits, digest=digest, interval=interval).verify(code)

    @staticmethod
    def get_provisioning_uri(
        secret: str,
        name: str,
        issuer_name: str,
        digits: int = 6,
        digest: Any = None,
        interval: int = 30,
        image: str | None = None,
    ) -> str:
        """Returns the provisioning URI for the OTP. This can then be encoded in a QR Code
        and used to provision an OTP app like Google Authenticator.

        :param secret: Secret in base32 format.
        :param name: Name of the account.
        :param issuer_name: The name of the OTP issuer; this will be the
                            organization title of the OTP entry in Authenticator.
        :param digits: Number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        :param digest: Digest function to use in the HMAC (expected to be SHA1)
        :param interval: The time interval in seconds for OTP. This defaults to 30.
        :param image: Optional logo image url.
        """
        return pyotp.TOTP(secret, digits=digits, digest=digest, interval=interval).provisioning_uri(
            name=name, issuer_name=issuer_name, image=image
        )


generate_key = pyotp.random_base32
generate_code = Rfc6238AuthenticationService.generate_code
get_provisioning_uri = Rfc6238AuthenticationService.get_provisioning_uri
validate_code = Rfc6238AuthenticationService.validate_code
