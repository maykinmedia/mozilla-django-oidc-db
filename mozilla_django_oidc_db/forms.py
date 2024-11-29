import json

from django import forms
from django.utils.translation import gettext_lazy as _

import requests

from .constants import OIDC_MAPPING, OPEN_ID_CONFIG_PATH
from .models import OpenIDConnectConfig


class OpenIDConnectConfigForm(forms.ModelForm):
    required_endpoints = [
        "oidc_op_authorization_endpoint",
        "oidc_op_token_endpoint",
        "oidc_op_user_endpoint",
    ]
    oidc_mapping = OIDC_MAPPING

    class Meta:
        model = OpenIDConnectConfig
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Only applicable if user has write access
        if self.fields:
            # Required endpoints should be optional in the form, if the can be
            # derived from the discovery endpoint
            for endpoint in self.required_endpoints:
                self.fields[endpoint].required = False

    @classmethod
    def get_endpoints_from_discovery(cls, base_url: str):
        response = requests.get(f"{base_url}{OPEN_ID_CONFIG_PATH}", timeout=10)
        response.raise_for_status()
        configuration = response.json()

        endpoints = {
            model_attr: configuration.get(oidc_attr)
            for model_attr, oidc_attr in cls.oidc_mapping.items()
        }
        return endpoints

    def clean(self):
        cleaned_data = super().clean()

        discovery_endpoint = cleaned_data.get("oidc_op_discovery_endpoint")

        # Derive the endpoints from the discovery endpoint
        if discovery_endpoint:
            try:
                endpoints = self.get_endpoints_from_discovery(discovery_endpoint)
                cleaned_data.update(**endpoints)
            except (
                requests.exceptions.RequestException,
                json.decoder.JSONDecodeError,
            ):
                raise forms.ValidationError(
                    {
                        "oidc_op_discovery_endpoint": _(
                            "Something went wrong while retrieving the configuration."
                        )
                    }
                )
        else:
            # Verify that the required endpoints were derived from the
            # discovery endpoint
            for field in self.required_endpoints:
                if not cleaned_data.get(field):
                    self.add_error(field, _("This field is required."))

        return cleaned_data
