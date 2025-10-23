import json
from collections.abc import Mapping
from urllib.parse import urljoin

from django import forms
from django.utils.translation import gettext_lazy as _

import requests

from .constants import OIDC_MAPPING, OPEN_ID_CONFIG_PATH
from .models import OIDCProvider
from .typing import EndpointFieldNames

type EndpointsMapping = Mapping[EndpointFieldNames, str]


class OIDCProviderForm(forms.ModelForm):
    required_endpoints = [
        "oidc_op_authorization_endpoint",
        "oidc_op_token_endpoint",
        "oidc_op_user_endpoint",
    ]
    oidc_mapping = OIDC_MAPPING

    class Meta:
        model = OIDCProvider
        fields = (
            "identifier",
            "oidc_op_discovery_endpoint",
            "oidc_op_jwks_endpoint",
            "oidc_op_authorization_endpoint",
            "oidc_op_token_endpoint",
            "oidc_op_user_endpoint",
            "oidc_op_logout_endpoint",
            "oidc_token_use_basic_auth",
            "oidc_use_nonce",
            "oidc_nonce_size",
            "oidc_state_size",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Only applicable if user has write access
        if self.fields:
            # Required endpoints should be optional in the form, if the can be
            # derived from the discovery endpoint
            for endpoint in self.required_endpoints:
                self.fields[endpoint].required = False

    @classmethod
    def get_endpoints_from_discovery(cls, base_url: str) -> EndpointsMapping:
        response = requests.get(urljoin(base_url, OPEN_ID_CONFIG_PATH), timeout=10)
        response.raise_for_status()
        configuration = response.json()

        endpoints: EndpointsMapping = {
            model_attr: endpoint
            for model_attr, oidc_attr in cls.oidc_mapping.items()
            if (endpoint := configuration.get(oidc_attr))
        }
        return endpoints

    def clean(self):
        super().clean()

        discovery_endpoint = self.cleaned_data.get("oidc_op_discovery_endpoint")

        # Derive the endpoints from the discovery endpoint
        if discovery_endpoint:
            try:
                endpoints = self.get_endpoints_from_discovery(discovery_endpoint)
                self.cleaned_data.update(**endpoints)
            except (
                requests.exceptions.RequestException,
                json.decoder.JSONDecodeError,
            ) as exc:
                raise forms.ValidationError(
                    {
                        "oidc_op_discovery_endpoint": _(
                            "Something went wrong while retrieving the configuration."
                        )
                    }
                ) from exc
        else:
            # Verify that the required endpoints were derived from the
            # discovery endpoint
            for field in self.required_endpoints:
                if not self.cleaned_data.get(field):
                    self.add_error(field, _("This field is required."))

        return self.cleaned_data
