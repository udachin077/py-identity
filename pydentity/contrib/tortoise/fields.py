from __future__ import annotations

from typing import TYPE_CHECKING, Any, override

from tortoise.fields import CharField

if TYPE_CHECKING:
    from pydentity.abc.data_protector import IPersonalDataProtector


class PersonalDataField(CharField):
    """A variably sized protected CharField.
    If a protector is installed, the data will be encrypted when writing and decrypted when receiving.
    """

    default_data_protector: IPersonalDataProtector | None = None

    def __init__(self, max_length: int, *, protector: IPersonalDataProtector | None = None, **kwargs: Any) -> None:
        self._protector = protector or self.default_data_protector
        super().__init__(max_length, **kwargs)

    @override
    def to_db_value(self, value, instance) -> Any:  # type: ignore[no-untyped-def]
        if value and self._protector:
            value = self._protector.protect(value)
        return value

    @override
    def to_python_value(self, value) -> Any:  # type: ignore[no-untyped-def]
        if value and self._protector:
            value = self._protector.unprotect(value)
        return value
