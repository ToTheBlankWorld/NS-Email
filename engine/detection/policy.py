"""Versioned policy configuration for the deterministic rule engine.

Policies are structured data validated through these typed models. Only
the built-in baseline is shipped; an operator may point
``NS_EMAIL_POLICY_FILE`` at a JSON policy file, which is parsed with the
stdlib JSON parser (no code execution) and validated against the same
models. Unknown keys are rejected, so a typo can never silently disable a
control.
"""

import json
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

BUILTIN_POLICY_ID: Final[str] = "securemailscope-baseline"
BUILTIN_POLICY_VERSION: Final[str] = "1.0"
MAX_POLICY_FILE_BYTES: Final[int] = 1_000_000

# Documented TLS version names accepted by the policy (matches the
# evidence model's version names; SSL 2.0/3.0 exist in the taxonomy).
KNOWN_TLS_VERSIONS: Final[frozenset[str]] = frozenset(
    {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"}
)


class TlsPolicy(BaseModel):
    """TLS version policy: the minimum version the baseline accepts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    minimum_version: str = "TLS 1.2"
    deprecated_versions: list[str] = Field(
        default_factory=lambda: ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"]
    )


class CipherSuitePolicy(BaseModel):
    """Cipher policy by registry classification.

    ``finding_classes`` lists cipher classes that produce findings (with
    deterministic severities: prohibited → critical, deprecated → medium,
    legacy → low). ``unknown`` is never treated as weak — an unknown suite
    produces an informational observation instead.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_classes: list[str] = Field(
        default_factory=lambda: ["prohibited", "deprecated", "legacy"]
    )


class KeyExchangePolicy(BaseModel):
    """Key-exchange policy: mechanisms the baseline does not accept."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    prohibited: list[str] = Field(default_factory=lambda: ["rsa", "dh", "ecdh"])


class CertificatePolicy(BaseModel):
    """Certificate policy: key strengths and signature algorithm classes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    minimum_rsa_bits: int = 2048
    minimum_dsa_bits: int = 2048
    minimum_ec_bits: int = 256
    weak_signature_algorithms: list[str] = Field(default_factory=lambda: ["md5", "sha1"])
    require_san_match_when_evidence_allows: bool = True
    warn_on_self_signed: bool = True


class ForwardSecrecyPolicy(BaseModel):
    """Forward-secrecy policy: whether the baseline requires it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    required: bool = True


class Policy(BaseModel):
    """A complete, versioned evaluation policy."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = BUILTIN_POLICY_ID
    version: str = BUILTIN_POLICY_VERSION
    tls: TlsPolicy = Field(default_factory=TlsPolicy)
    cipher_suites: CipherSuitePolicy = Field(default_factory=CipherSuitePolicy)
    key_exchange: KeyExchangePolicy = Field(default_factory=KeyExchangePolicy)
    certificates: CertificatePolicy = Field(default_factory=CertificatePolicy)
    forward_secrecy: ForwardSecrecyPolicy = Field(default_factory=ForwardSecrecyPolicy)


_POLICY_DATA_DIR: Final[Path] = Path(__file__).parent / "data"
BUILTIN_POLICY_FILE: Final[Path] = (
    _POLICY_DATA_DIR / f"{BUILTIN_POLICY_ID}-v{BUILTIN_POLICY_VERSION}.json"
)


def _parse_policy_document(document: str, origin: str) -> Policy:
    if len(document) > MAX_POLICY_FILE_BYTES:
        raise ValueError(f"policy document exceeds {MAX_POLICY_FILE_BYTES} bytes: {origin}")
    try:
        payload = json.loads(document)
    except json.JSONDecodeError as error:
        raise ValueError(f"policy is not valid JSON ({origin}): {error}") from error
    try:
        return Policy.model_validate(payload)
    except Exception as error:
        raise ValueError(f"policy failed validation ({origin}): {error}") from error


def load_builtin_policy() -> Policy:
    """Load the versioned built-in baseline policy."""
    return _parse_policy_document(BUILTIN_POLICY_FILE.read_text(encoding="utf-8"), "builtin")


def load_policy_from_file(path: Path) -> Policy:
    """Load a custom policy from a JSON file (operator-provided path).

    The file is read with a hard size bound and parsed as structured JSON
    validated against the typed policy models — no code execution path
    exists. Raises ``ValueError`` with a clear message on any problem.
    """
    try:
        document = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(f"cannot read policy file {path}: {error}") from error
    return _parse_policy_document(document, str(path))
