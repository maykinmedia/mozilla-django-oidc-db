from django.urls import reverse

from .utils import keycloak_login

KEYCLOAK_BASE_URL = "http://localhost:8080/realms/test/"


def test_client_id_secret_full_flow(keycloak_config, client, django_user_model):
    login_url = reverse("login")
    django_login_response = client.get(login_url)
    assert django_login_response.status_code, 302

    # simulate login to Keycloak
    redirect_uri = keycloak_login(django_login_response["Location"])

    # complete the login flow on our end
    callback_response = client.get(redirect_uri)

    assert callback_response.status_code == 302
    assert callback_response["Location"] == "/admin/"

    # a user was created
    assert django_user_model.objects.count() == 1
