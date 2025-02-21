from pydentity.abc.data_protector import IDataProtector, IPersonalDataProtector
from pydentity.encryption.data_protectors import AESDataProtector
from pydentity.utils import ensure_str

__all__ = ["PersonalDataProtector"]


class PersonalDataProtector(IPersonalDataProtector):
    def __init__(
        self,
        key_or_protector: str | bytes | IDataProtector,
        key_salt: str | bytes = b"personal.protector",
    ) -> None:
        if isinstance(key_or_protector, IDataProtector):
            self._protector = key_or_protector
        else:
            self._protector = AESDataProtector(key=key_or_protector, salt=key_salt)

    def protect(self, data: str | bytes) -> str:
        return ensure_str(self._protector.encrypt(data))

    def unprotect(self, data: str | bytes) -> str:
        return ensure_str(self._protector.decrypt(data))
