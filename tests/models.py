from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from uuid_extensions import uuid7str

from pydentity.models import RoleProtokol, UserProtokol


@dataclass
class MockUser(UserProtokol):
    email: Optional[str]
    username: Optional[str]
    access_failed_count: int = 0
    concurrency_stamp: Optional[str] = None
    email_confirmed: bool = False
    id: str = field(default_factory=uuid7str)
    lockout_enabled: bool = True
    lockout_end: Optional[datetime] = None
    normalized_email: Optional[str] = None
    normalized_username: Optional[str] = None
    password_hash: Optional[str] = None
    phone_number: Optional[str] = None
    phone_number_confirmed: bool = False
    security_stamp: Optional[str] = field(default_factory=uuid7str)
    two_factor_enabled: bool = False

    def __post_init__(self):
        self.normalized_email = self.email.upper()
        self.normalized_username = self.username.upper()


@dataclass
class MockRole(RoleProtokol):
    name: Optional[str]
    concurrency_stamp: Optional[str] = None
    id: str = field(default_factory=uuid7str)
    normalized_name: Optional[str] = None

    def __post_init__(self):
        self.normalized_name = self.name.upper()
