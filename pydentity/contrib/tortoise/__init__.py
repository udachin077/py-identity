from pydentity.abc.data_protector import IPersonalDataProtector
from pydentity.contrib.tortoise.fields import PersonalDataField
from pydentity.exc import NotSupportedError

__all__ = ["use_personal_data_protector"]


def use_personal_data_protector(protector: IPersonalDataProtector) -> None:
    """Sets the *IDataProtector* for *PersonalDataField* fields.
    When using the function, a protector will be installed,
    the data will be encrypted when writing and decrypted when receiving.
    If the value of protector is None, the default protector will be set.

    :param protector:
    :return:
    """
    if not protector or not issubclass(type(protector), IPersonalDataProtector):
        raise NotSupportedError("The 'protector' must implement the 'IPersonalDataProtector' interface.")
    PersonalDataField.default_data_protector = protector
