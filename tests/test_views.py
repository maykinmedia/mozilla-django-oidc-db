from django.test import Client
from django.urls import reverse


def test_error_page_direct_access_forbidden(client: Client):
    # error information needs to be in the session to have access
    error_url = reverse("admin-oidc-error")

    response = client.get(error_url)

    assert response.status_code == 403
