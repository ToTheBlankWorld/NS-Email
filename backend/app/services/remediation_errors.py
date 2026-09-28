"""Remediation workflow errors (Stage 13)."""


class RemediationNotFoundError(Exception):
    """The requested remediation id is unknown (covers malformed ids too)."""

    def __init__(self, remediation_id: str) -> None:
        super().__init__("no remediation exists with this id")
        self.remediation_id = remediation_id


class VerificationNotFoundError(Exception):
    """The requested verification id is unknown (covers malformed ids too)."""

    def __init__(self, verification_id: str) -> None:
        super().__init__("no verification exists with this id")
        self.verification_id = verification_id
