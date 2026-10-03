"""Tests for passive leaked-secret detection."""
from darkosint.secrets import (
    CREDENTIAL_PAIR,
    SECRET_API_TOKEN,
    SECRET_ASSIGNMENT,
    SECRET_PRIVATE_KEY,
    extract_secrets,
    mask,
    redact_secrets,
)


def _types(text):
    return {i.type for i in extract_secrets(text)}


def test_detects_private_key_block():
    text = ("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n"
            "-----END RSA PRIVATE KEY-----")
    ids = extract_secrets(text, "http://x.onion/")
    assert len(ids) == 1 and ids[0].type == SECRET_PRIVATE_KEY


def test_detects_provider_tokens():
    text = "key AKIAIOSFODNN7EXAMPLE and ghp_" + "a" * 36 + " and AIza" + "b" * 35
    assert _types(text) == {SECRET_API_TOKEN}
    assert len(extract_secrets(text)) == 3


def test_detects_credential_dump_line():
    ids = extract_secrets("victim@mail.test:Winter2024!")
    assert ids and ids[0].type == CREDENTIAL_PAIR


def test_detects_secret_assignment_including_underscored_keys():
    assert SECRET_ASSIGNMENT in _types("DB_PASSWORD=Sup3rSecret99")
    assert SECRET_ASSIGNMENT in _types("api_key: 9a8b7c6d5e4f3g2h")


def test_ignores_placeholders():
    for junk in ("password=changeme", "secret=your-secret-here",
                 "api_key=xxxxxxxx", "token=${ENV_TOKEN}"):
        assert not extract_secrets(junk), junk


def test_value_is_hashed_never_plaintext():
    """The queryable value must not contain the secret in the clear."""
    secret = "AKIAIOSFODNN7EXAMPLE"
    ident = extract_secrets(f"key={secret}")[0]
    assert ident.value.startswith("sha256:")
    assert secret not in ident.value
    # The masked preview also hides the middle.
    assert secret not in ident.context
    assert "AKIA" in ident.context and "…" in ident.context


def test_mask_hides_the_middle_and_flags_pem():
    assert mask("AKIAIOSFODNN7EXAMPLE").startswith("AKIA…")
    assert "PEM private-key block" in mask("-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----")
    assert mask("") == ""


def test_findings_are_flagged_heuristic():
    for ident in extract_secrets("admin@corp.test:hunter2pass\nAKIAIOSFODNN7EXAMPLE"):
        assert ident.heuristic


def test_empty_and_clean_text_yield_nothing():
    assert extract_secrets("") == []
    assert extract_secrets("just some ordinary prose with no secrets in it") == []


def test_mask_fully_hides_short_secrets():
    """A short password must not have most of itself revealed by the preview."""
    # Under 12 chars: reveal nothing but the length.
    assert mask("hunter2x9") == "<9 chars>"
    assert mask("qwerty12345") == "<11 chars>"
    # 12-15 chars: only two at each end.
    assert mask("Winter2024pass") == "Wi…ss (14 chars)"
    # No preview should ever contain the whole secret.
    for secret in ("hunter2x9", "qwerty12345", "Winter2024pass"):
        assert secret not in mask(secret)


def test_redaction_removes_plaintext_but_keeps_findings():
    """redact_secrets must blank every secret in the returned text while still
    reporting each as a hashed, flagged finding — the DB-safe path."""
    text = (
        "alice@example.com:Winter2024pass\n"
        "db_password = HorseBattery99\n"
        "token AKIAIOSFODNN7EXAMPLE\n"
    )
    redacted, findings = redact_secrets(text, "http://x.onion/")

    # No plaintext secret survives in the redacted text...
    for plaintext in ("Winter2024pass", "HorseBattery99", "AKIAIOSFODNN7EXAMPLE"):
        assert plaintext not in redacted
    # ...but the account half of a combolist line (a real identifier) stays.
    assert "alice@example.com" in redacted
    assert "REDACTED" in redacted

    # Every finding is hashed, masked, and flagged for review.
    assert {f.type for f in findings} == {
        CREDENTIAL_PAIR, SECRET_ASSIGNMENT, SECRET_API_TOKEN,
    }
    for f in findings:
        assert f.value.startswith("sha256:") and f.heuristic


def test_digest_is_keyed_and_stable_within_a_run():
    """Identical secrets dedupe (same digest); different secrets do not collide."""
    a = extract_secrets("key AKIAIOSFODNN7EXAMPLE")[0]
    b = extract_secrets("other line key AKIAIOSFODNN7EXAMPLE")[0]
    c = extract_secrets("key AKIAIOSFODNN7DIFFE1X")[0]  # a different valid AWS id
    assert a.value == b.value          # same secret -> same digest (dedup/pivot)
    assert a.value != c.value          # different secret -> different digest
