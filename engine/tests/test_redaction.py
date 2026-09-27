"""Tests for credential redaction at the storage boundary."""

from engine.protocols.redaction import command_and_args, redact_arguments, redact_line


def test_sensitive_commands_are_redacted() -> None:
    for command in ("USER", "PASS", "AUTH", "LOGIN", "AUTHENTICATE"):
        assert redact_arguments(command, "anything-secret") == "redacted"


def test_envelope_addresses_are_preserved_but_sanitized() -> None:
    assert redact_arguments("MAIL", "FROM:<alice@example.net>") == "FROM:<alice@example.net>"


def test_redact_line_removes_credentials_from_diagnostics() -> None:
    assert redact_line("PASS hunter2") == "PASS redacted"
    assert redact_line("USER dave@example.net") == "USER redacted"
    # non-sensitive lines pass through sanitized
    assert redact_line("CAPABILITY") == "CAPABILITY"


def test_command_and_args_splits_on_first_whitespace() -> None:
    assert command_and_args("EHLO client.example.net") == ("EHLO", "client.example.net")
    assert command_and_args("QUIT") == ("QUIT", "")
    assert command_and_args("") == ("", "")
