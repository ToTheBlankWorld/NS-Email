"""Cipher suite registry and cryptographic fact mapping.

Maps wire codes to standard names and derives the key-exchange family of
a selected suite. Pure lookup tables — no scoring, no verdicts.
"""

from typing import Final

from engine.core.tls import KeyExchange

# IANA TLS cipher suites commonly observed in the wild.
CIPHER_SUITE_NAMES: Final[dict[int, str]] = {
    # TLS 1.3
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    # ECDHE
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    # DHE
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0034: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    # Static RSA / ECDH
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    0xC029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
}

_CIPHER_SUITE_FAMILY: Final[list[tuple[str, KeyExchange]]] = [
    ("TLS_AES_", KeyExchange.TLS_1_3),
    ("TLS_CHACHA20_", KeyExchange.TLS_1_3),
    ("TLS_ECDHE_", KeyExchange.ECDHE),
    ("TLS_ECDH_", KeyExchange.ECDH),
    ("TLS_DHE_", KeyExchange.DHE),
    ("TLS_DH_", KeyExchange.DH),
    ("TLS_RSA_", KeyExchange.RSA),
]


def cipher_suite_name(code: int) -> str:
    """Standard suite name for a wire code, or a ``0x…`` fallback."""
    return CIPHER_SUITE_NAMES.get(code, f"0x{code:04X}")


def key_exchange_for_suite(name: str) -> KeyExchange:
    """Derive the key-exchange family from a suite's standard name.

    TLS 1.3 suites always negotiate ephemeral key material; classical
    suites carry their key-exchange family in the name prefix.
    """
    for prefix, key_exchange in _CIPHER_SUITE_FAMILY:
        if name.startswith(prefix):
            return key_exchange
    return KeyExchange.UNKNOWN


# TLS/SSL protocol version wire bytes → canonical names.
VERSION_NAMES: Final[dict[int, str]] = {
    0x0002: "SSL 2.0",
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# Well-known TLS hello extension types.
EXTENSION_NAMES: Final[dict[int, str]] = {
    0: "server_name",
    1: "max_fragment_length",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    15: "heartbeat",
    16: "application_layer_protocol_negotiation",
    21: "padding",
    22: "encrypt_then_mac",
    23: "extended_master_secret",
    35: "session_ticket",
    41: "pre_shared_key",
    43: "supported_versions",
    45: "psk_key_exchange_modes",
    51: "key_share",
    0xFF01: "renegotiation_info",
}

# Named groups (RFC 8446 / RFC 4492) for supported_groups summaries.
GROUP_NAMES: Final[dict[int, str]] = {
    19: "secp224r1",
    20: "secp256r1",
    21: "secp384r1",
    22: "secp521r1",
    23: "secp256k1",
    24: "ffdhe2048",
    25: "ffdhe3072",
    29: "x25519",
    30: "x448",
}

SIGNATURE_ALGORITHM_NAMES: Final[dict[int, str]] = {
    0x0401: "rsa_pkcs1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
}
