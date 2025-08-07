from django import template

from ..constants import OIDC_ADMIN_CONFIG_IDENTIFIER
from ..models import OIDCClient

register = template.Library()


@register.simple_tag
def get_oidc_admin_client() -> OIDCClient | None:
    return OIDCClient.objects.filter(identifier=OIDC_ADMIN_CONFIG_IDENTIFIER).first()
