from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import TestCase
from django.urls import reverse

from mozilla_django_oidc_db.models import OpenIDConnectConfig

from .factories import StaffUserFactory

User = get_user_model()


class OIDCFlowTests(TestCase):
    @patch(
        "mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.get_or_create_user"
    )
    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.get_userinfo")
    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.store_tokens")
    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.verify_token")
    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.get_token")
    @patch(
        "mozilla_django_oidc_db.mixins.OpenIDConnectConfig.get_solo",
        return_value=OpenIDConnectConfig(enabled=True),
    )
    def test_duplicate_email_unique_constraint_violated(
        self,
        mock_get_solo,
        mock_get_token,
        mock_verify_token,
        mock_store_tokens,
        mock_get_userinfo,
        mock_get_or_create_user,
    ):
        """
        Assert that duplicate email addresses result in usable user feedback.
        """
        mock_get_or_create_user.side_effect = IntegrityError(
            """duplicate key value violates unique constraint "filled_email_unique"""
            """"\nDETAIL:  Key (email)=(collision@example.com) already exists.\n"""
        )
        # set up a user with a colliding email address
        mock_get_userinfo.return_value = {
            "email": "collision@example.com",
            "sub": "some_username",
        }
        StaffUserFactory.create(
            username="nonmatchingusername", email="collision@example.com"
        )
        session = self.client.session
        session["oidc_states"] = {"mock": {"nonce": "nonce"}}
        session.save()
        callback_url = reverse("oidc_authentication_callback")

        # enter the login flow
        callback_response = self.client.get(
            callback_url, {"code": "mock", "state": "mock"}
        )

        error_url = reverse("admin-oidc-error")

        with self.subTest("error redirects"):
            self.assertRedirects(callback_response, error_url)

        with self.subTest("exception info on error page"):
            error_page = self.client.get(error_url)

            self.assertEqual(error_page.status_code, 200)
            self.assertEqual(
                error_page.context["oidc_error"],
                """duplicate key value violates unique constraint "filled_email_unique"""
                """"\nDETAIL:  Key (email)=(collision@example.com) already exists.\n""",
            )
            self.assertContains(
                error_page, "duplicate key value violates unique constraint"
            )

    @patch(
        "mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.get_or_create_user"
    )
    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.get_userinfo")
    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.store_tokens")
    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.verify_token")
    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.get_token")
    @patch(
        "mozilla_django_oidc_db.mixins.OpenIDConnectConfig.get_solo",
        return_value=OpenIDConnectConfig(enabled=True),
    )
    def test_validation_error_during_authentication(
        self,
        mock_get_solo,
        mock_get_token,
        mock_verify_token,
        mock_store_tokens,
        mock_get_userinfo,
        mock_get_or_create_user,
    ):
        """
        Assert that ValidationErrors raised during the auth process
        result in usable user feedback.
        """
        mock_get_or_create_user.side_effect = ValidationError(
            "Waarde van %(value)s moet True of False zijn."
        )
        # set up a user with a colliding email address
        mock_get_userinfo.return_value = {
            "email": "admin@example.com",
            "sub": "some_username",
        }
        StaffUserFactory.create(username="some_username", email="admin@example.com")
        session = self.client.session
        session["oidc_states"] = {"mock": {"nonce": "nonce"}}
        session.save()
        callback_url = reverse("oidc_authentication_callback")

        # enter the login flow
        callback_response = self.client.get(
            callback_url, {"code": "mock", "state": "mock"}
        )

        error_url = reverse("admin-oidc-error")

        with self.subTest("error redirects"):
            self.assertRedirects(callback_response, error_url)

        with self.subTest("exception info on error page"):
            error_page = self.client.get(error_url)

            self.assertEqual(error_page.status_code, 200)
            self.assertEqual(
                error_page.context["oidc_error"],
                "Waarde van %(value)s moet True of False zijn.",
            )
            self.assertContains(
                error_page, "Waarde van %(value)s moet True of False zijn."
            )

    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.get_userinfo")
    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.store_tokens")
    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.verify_token")
    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.get_token")
    @patch(
        "mozilla_django_oidc_db.mixins.OpenIDConnectConfig.get_solo",
        return_value=OpenIDConnectConfig(id=1, enabled=True),
    )
    def test_happy_flow(
        self,
        mock_get_solo,
        mock_get_token,
        mock_verify_token,
        mock_store_tokens,
        mock_get_userinfo,
    ):
        """
        Assert that duplicate email addresses result in usable user feedback.
        """
        # set up a user with a colliding email address
        mock_get_userinfo.return_value = {
            "email": "nocollision@example.com",
            "sub": "some_username",
        }
        StaffUserFactory.create(
            username="nonmatchingusername", email="collision@example.com"
        )
        session = self.client.session
        session["oidc_states"] = {"mock": {"nonce": "nonce"}}
        session.save()
        callback_url = reverse("oidc_authentication_callback")

        # enter the login flow
        callback_response = self.client.get(
            callback_url, {"code": "mock", "state": "mock"}
        )

        self.assertRedirects(
            callback_response, reverse("admin:index"), fetch_redirect_response=False
        )
        self.assertTrue(User.objects.filter(email="nocollision@example.com").exists())

    def test_error_page_direct_access_forbidden(self):
        error_url = reverse("admin-oidc-error")

        response = self.client.get(error_url)

        self.assertEqual(response.status_code, 403)

    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.get_userinfo")
    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.store_tokens")
    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.verify_token")
    @patch("mozilla_django_oidc_db.backends.OIDCAuthenticationBackend.get_token")
    @patch(
        "mozilla_django_oidc_db.mixins.OpenIDConnectConfig.get_solo",
        return_value=OpenIDConnectConfig(id=1, enabled=True),
    )
    def test_error_first_cleared_after_succesful_login(
        self,
        mock_get_solo,
        mock_get_token,
        mock_verify_token,
        mock_store_tokens,
        mock_get_userinfo,
    ):
        mock_get_userinfo.return_value = {
            "email": "nocollision@example.com",
            "sub": "some_username",
        }
        session = self.client.session
        session["oidc-error"] = "some error"
        session.save()
        error_url = reverse("admin-oidc-error")

        with self.subTest("with error"):
            response = self.client.get(error_url)

            self.assertEqual(response.status_code, 200)

        with self.subTest("after succesful login"):
            session["oidc_states"] = {"mock": {"nonce": "nonce"}}
            session.save()
            callback_url = reverse("oidc_authentication_callback")

            # enter the login flow
            callback_response = self.client.get(
                callback_url, {"code": "mock", "state": "mock"}
            )

            self.assertRedirects(
                callback_response, reverse("admin:index"), fetch_redirect_response=False
            )

            with self.subTest("check error page again"):
                response = self.client.get(error_url)

                self.assertEqual(response.status_code, 403)
