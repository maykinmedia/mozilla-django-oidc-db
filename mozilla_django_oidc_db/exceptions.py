from __future__ import annotations

from typing import TYPE_CHECKING

from .typing import ClaimPath, JSONObject

if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractUser


class OIDCProviderOutage(Exception):
    pass


class MissingIdentifierClaim(Exception):
    def __init__(self, claim_bits: ClaimPath, *args, **kwargs):
        self.claim_bits = claim_bits
        super().__init__(*args, **kwargs)


class MissingInitialisation(Exception):
    pass


class AccountMergeRequired(Exception):
    """
    Raised during OIDC authentication when an existing Django account shares the
    same email address as the OIDC identity, but the username does not match.

    Raising this exception interrupts the normal OIDC callback flow and triggers
    the one-time account-merge onboarding process, where the user must confirm
    ownership of the existing account by providing their current password.

    Only raised when ``allow_account_merge`` is enabled on the :class:`OIDCClient`.
    """

    def __init__(self, candidate: AbstractUser, claims: JSONObject):
        self.candidate = candidate
        self.claims = claims
        super().__init__()
