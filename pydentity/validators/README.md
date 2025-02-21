## Validators

The module implements standard validators (`pyidentity.validators`):

* **UserValidator** : provides validation builders for user
  classes ([email-validator](https://github.com/JoshData/python-email-validator) is used for email validation).
* **RoleValidator** : provides validation builders for role classes.
* **PasswordValidator** : provides the default password policy for PyIdentity.

### Custom validators

Implement the interface `IUserValidator`, `IRoleValidator` or `IPasswordValidator`.

```python
from typing import Generic

from pydentity import IdentityResult, UserManager, RoleManager
from pydentity.abc.validators import IUserValidator, IRoleValidator, IPasswordValidator
from pydentity.models import UserT, RoleT


class MyUserValidator(IUserValidator[UserT], Generic[UserT]):
  async def validate(self, manager: UserManager[UserT], user: UserT) -> IdentityResult:
    ...


class MyRoleValidator(IRoleValidator[UserT], Generic[UserT]):
  async def validate(self, manager: RoleManager[RoleT], role: RoleT) -> IdentityResult:
    ...


class MyPasswordValidator(IPasswordValidator[UserT], Generic[UserT]):
  async def validate(self, manager: UserManager[UserT], password: str) -> IdentityResult:
    ...
```

Inherit the `UserValidator`, `RoleValidator`, `PasswordValidator` class.

```python
from typing import Generic, override

from pydentity import IdentityResult, UserManager, RoleManager
from pydentity.models import UserT, RoleT
from pydentity.validators import RoleValidator, UserValidator, PasswordValidator


class CustomUserValidator(UserValidator[UserT], Generic[UserT]):
  @override
  async def validate(self, manager: UserManager[UserT], user: UserT) -> IdentityResult:
    ...


class CustomRoleValidator(RoleValidator[UserT], Generic[UserT]):
  @override
  async def validate(self, manager: RoleManager[RoleT], role: RoleT) -> IdentityResult:
    ...


class CustomPasswordValidator(PasswordValidator[UserT], Generic[UserT]):
  @override
  async def validate(self, manager: UserManager[UserT], password: str) -> IdentityResult:
    ...
```