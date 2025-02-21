from pydentity.lookup_normalizer import LowerLookupNormalizer, UpperLookupNormalizer


def test_upper_lookup_normalizer():
    normalizer = UpperLookupNormalizer()
    assert normalizer.normalize_name("John.Anderson@mail.example") == "John.Anderson@mail.example".upper()
    assert normalizer.normalize_email("John.Anderson@mail.example") == "John.Anderson@mail.example".upper()
    assert normalizer.normalize_name(None) is None
    assert normalizer.normalize_email(None) is None


def test_lower_lookup_normalizer():
    normalizer = LowerLookupNormalizer()
    assert normalizer.normalize_name("John.Anderson@mail.example") == "John.Anderson@mail.example".lower()
    assert normalizer.normalize_email("John.Anderson@mail.example") == "John.Anderson@mail.example".lower()
    assert normalizer.normalize_name(None) is None
    assert normalizer.normalize_email(None) is None
