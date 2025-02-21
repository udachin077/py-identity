from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase

__all__ = ["Model"]


class Model(AsyncAttrs, DeclarativeBase):
    pass
