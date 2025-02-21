## Password hashers

Password hasher uses [pwdlib](https://github.com/frankie567/pwdlib).

* Bcrypt
* Argon2
* PBKDF2

### Custom password hasher

Implement the interface `IPasswordHasher`.

```python
from typing import Generic

from pydentity.abc import IPasswordHasher
from pydentity.models import UserT
from pydentity.password_hashers import PasswordVerificationResult


class CustomPasswordHasher(IPasswordHasher[UserT], Generic[UserT]):
    def hash_password(self, user: UserT, password: str) -> str:
        ...

    def verify_hashed_password(
            self,
            user: UserT,
            hashed_password: str,
            password: str
    ) -> PasswordVerificationResult:
        ...
```

Inherit the `PasswordHasher` class.

```python
from typing import Generic

from pydentity.models import UserT
from pydentity.password_hashers import PasswordHasher
from pydentity.password_hashers.hashers import HasherProtocol


class MyHasher(HasherProtocol):
    ...


class MyPasswordHasher(PasswordHasher[UserT], Generic[UserT]):
    def __init__(self):
        super().__init__((MyHasher(),))
```