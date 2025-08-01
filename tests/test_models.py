from mozilla_django_oidc_db.fields import ClaimFieldDefault


def test_claim_field_default_equality():
    assert ClaimFieldDefault("foo", "bar") == ClaimFieldDefault("foo", "bar")
    assert ClaimFieldDefault("foo", "bar") != ClaimFieldDefault("bar", "foo")
