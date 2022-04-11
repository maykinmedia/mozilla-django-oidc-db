from mozilla_django_oidc_db.utils import obfuscate_claim_value, obfuscate_claims


def test_obfuscate_string():
    value = "123456782"
    result = obfuscate_claim_value(value)

    assert result == "*******82"


def test_obfuscate_non_string():
    value = 12345
    result = obfuscate_claim_value(value)

    assert result == "****5"


def test_obfuscate_nested():
    claims = {
        "foo": "not_obfuscated",
        "some": {
            "nested": {
                "claim": "obfuscated",
                "claim2": "not_obfuscated",
            }
        },
        "object": {
            "foo": "obfuscated",
            "bar": "obfuscated",
        },
    }
    claims_to_obfuscate = ["some.nested.claim", "object"]
    expected_result = {
        "foo": "not_obfuscated",
        "some": {"nested": {"claim": "********ed", "claim2": "not_obfuscated"}},
        "object": {"foo": "********ed", "bar": "********ed"},
    }

    result = obfuscate_claims(claims, claims_to_obfuscate)

    assert result == expected_result
