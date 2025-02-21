from __future__ import annotations

from typing import TYPE_CHECKING, Any, override

from sqlalchemy import String, TypeDecorator

if TYPE_CHECKING:
    from pydentity.abc.data_protector import IPersonalDataProtector


class PersonalDataField(TypeDecorator[str]):
    """A variably sized protected string type.
    If a protector is installed, the data will be encrypted when writing and decrypted when receiving.
    """

    impl = String
    cache_ok = True
    default_protector: IPersonalDataProtector | None = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._protector = kwargs.pop("protector", self.default_protector)
        super().__init__(*args, **kwargs)

    @override
    def process_bind_param(self, value, dialect) -> Any:  # type: ignore[no-untyped-def]
        if value and self._protector:
            value = self._protector.protect(value)
        return value

    @override
    def process_result_value(self, value, dialect) -> Any:  # type: ignore[no-untyped-def]
        if value and self._protector:
            value = self._protector.unprotect(value)
        return value
