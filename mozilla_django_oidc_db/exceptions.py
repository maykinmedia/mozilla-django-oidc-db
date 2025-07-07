from .typing import ClaimPath


class OIDCProviderOutage(Exception):
    pass


class MissingIdentifierClaim(Exception):
    def __init__(self, claim_bits: ClaimPath, *args, **kwargs):
        self.claim_bits = claim_bits
        super().__init__(*args, **kwargs)


class MissingInitialisation(Exception):
    pass
