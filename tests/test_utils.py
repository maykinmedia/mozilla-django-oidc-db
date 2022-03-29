from mozilla_django_oidc_db.utils import obfuscate_claim


def test_obfuscate_string():
    value = "123456782"
    result = obfuscate_claim(value)

    assert result == "*******82"


def test_obfuscate_non_string():
    value = 12345
    result = obfuscate_claim(value)

    assert result == "****5"
