## Token providers

The module implements standard validators (`pyidentity.token_providers`):

Supports TOPT (used [pyotp](https://github.com/pyauth/pyotp)):

* **AuthenticatorTokenProvider**
* **EmailTokenProvider**
* **PhoneNumberTokenProvider**

Not supports TOPT:

* **DataProtectorTokenProvider**

### Custom token provider

Implement the interface `IUserTwoFactorTokenProvider`.

```python
from typing import Generic

from pydentity import UserManager
from pydentity.abc import IUserTwoFactorTokenProvider
from pydentity.models import UserT


class MyTokenProvider(IUserTwoFactorTokenProvider[UserT], Generic[UserT]):
    async def generate(self, manager: UserManager[UserT], purpose: str, user: UserT) -> str:
        ...

    async def validate(self, manager: UserManager[UserT], purpose: str, token: str, user: UserT) -> bool:
        ...

    async def can_generate_two_factor(self, manager: UserManager[UserT], user: UserT) -> bool:
        ...
```

Inherit the `TotpSecurityStampBasedTokenProvider` class.

```python
from typing import Generic, override

from pydentity import UserManager
from pydentity.models import UserT
from pydentity.token_providers import TotpSecurityStampBasedTokenProvider


class MyTokenProvider(TotpSecurityStampBasedTokenProvider[UserT], Generic[UserT]):
    @override
    async def generate(self, manager: UserManager[UserT], purpose: str, user: UserT) -> str:
        ...

    @override
    async def validate(self, manager: UserManager[UserT], purpose: str, token: str, user: UserT) -> bool:
        ...

    @override
    async def can_generate_two_factor(self, manager: UserManager[UserT], user: UserT) -> bool:
        ...
```