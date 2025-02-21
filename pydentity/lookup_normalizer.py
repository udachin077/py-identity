from pydentity.abc.lookup_normalizer import ILookupNormalizer

__all__ = ["LowerLookupNormalizer", "UpperLookupNormalizer"]


class UpperLookupNormalizer(ILookupNormalizer):
    """Converting keys to their upper case representation."""

    def normalize_email(self, email: str | None) -> str | None:
        return email.upper() if email else email

    def normalize_name(self, name: str | None) -> str | None:
        return name.upper() if name else name


class LowerLookupNormalizer(ILookupNormalizer):
    """Converting keys to their lower case representation."""

    def normalize_email(self, email: str | None) -> str | None:
        return email.lower() if email else email

    def normalize_name(self, name: str | None) -> str | None:
        return name.lower() if name else name
