"""Exposed-secret and leaked-credential detection — passive.

A dark web threat-intelligence tool's job around credentials is not to *obtain*
them — it is to notice when they have already been leaked into content the
collector was served. Marketplaces and forums trade credential dumps; a
misconfigured origin page occasionally serves its own `.env`; a paste leaks an
API token. Detecting those in material already collected is squarely defensive.

This module runs over already-fetched text. It never authenticates, never
requests a protected resource, and never goes looking for admin endpoints — it
reads what was served and flags credential-shaped artifacts in it, exactly like
the exposure-note mechanism it sits beside.

Handling discipline
-------------------
The tool must not itself become a place that stores or displays live secrets in
the clear. So each finding carries:

* ``value``   — a keyed ``sha256:`` digest of the secret, so identical leaks
                dedupe and pivot across sources **without** the plaintext living
                in the DB, and without the digest being reversible by a
                dictionary attack (it is an HMAC under a per-install key);
* ``context`` — a *masked* preview (``AKIA…XZ4Q``) plus where it was seen.

Two functions produce findings:

* :func:`extract_secrets` returns the findings for a block of text.
* :func:`redact_secrets` returns the same findings **and** a copy of the text
  with every secret span blanked, so the caller can store that redacted copy
  (documents, identifier contexts) instead of the original. The full string then
  lives only in the raw on-disk snapshot (the evidentiary record), never in the
  queryable database or the dashboard.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .extractors import Identifier

logger = logging.getLogger("darkosint.secrets")

# ---- identifier type constants -------------------------------------------

SECRET_PRIVATE_KEY = "secret_private_key"
SECRET_API_TOKEN = "secret_api_token"
SECRET_ASSIGNMENT = "secret_assignment"
CREDENTIAL_PAIR = "credential_pair"

SECRET_TYPES = (
    SECRET_PRIVATE_KEY, SECRET_API_TOKEN, SECRET_ASSIGNMENT, CREDENTIAL_PAIR,
)

#: Placeholder substituted for a secret span in redacted text. Carries the first
#: eight hex of the (keyed) digest so an analyst can still tie a redaction back
#: to the corresponding hashed finding without ever seeing the plaintext.
REDACTION_TEMPLATE = "«REDACTED:{label}:{digest8}»"


# ---- keyed hashing --------------------------------------------------------
#
# A plain SHA-256 of "email:password" is reversible in seconds against a
# wordlist — for a combolist of weak passwords that defeats the whole point of
# hashing. Keying the hash (HMAC) under a secret only this installation holds
# keeps cross-source dedup/pivot working while making the stored digest useless
# to anyone who lifts the database without also having the key.

_HMAC_KEY: bytes | None = None


def _secret_key() -> bytes:
    """Resolve (and cache) the per-install HMAC key.

    Order: ``DARKOSINT_SECRET_HMAC_KEY`` env var -> a persisted key file under
    ``~/.darkosint/`` (created 0600 on first use) -> an ephemeral process key if
    neither is available. The persisted key is what lets identical leaks dedupe
    across runs; an ephemeral fallback still dedupes within a single run.
    """
    global _HMAC_KEY
    if _HMAC_KEY is not None:
        return _HMAC_KEY

    env = os.environ.get("DARKOSINT_SECRET_HMAC_KEY")
    if env:
        _HMAC_KEY = env.encode("utf-8")
        return _HMAC_KEY

    try:
        keydir = Path(os.path.expanduser("~/.darkosint"))
        keydir.mkdir(parents=True, exist_ok=True)
        keyfile = keydir / "secret_hmac.key"
        if keyfile.exists():
            _HMAC_KEY = keyfile.read_bytes()
        else:
            _HMAC_KEY = os.urandom(32)
            keyfile.write_bytes(_HMAC_KEY)
            try:
                os.chmod(keyfile, 0o600)
            except OSError:  # pragma: no cover - platform dependent
                pass
    except OSError:  # pragma: no cover - home dir not writable
        _HMAC_KEY = os.urandom(32)
        logger.warning(
            "Could not persist a secret HMAC key; using an ephemeral key. "
            "Leaked-secret digests will not dedupe across separate runs."
        )
    return _HMAC_KEY


def mask(secret: str) -> str:
    """Mask a secret for display: reveal a little only when it is long enough.

    Short secrets are the dangerous case — revealing four characters at each end
    of a nine-character password exposes almost all of it — so the amount shown
    scales with length: nothing but the length under 12 characters, two ends of
    two below 16, four and four above that (long provider tokens whose leading
    bytes are a fixed, non-secret prefix like ``AKIA``).
    """
    s = secret.strip()
    if "PRIVATE KEY" in s:
        return f"<PEM private-key block, {len(s)} chars>"
    if not s:
        return ""
    n = len(s)
    if n < 12:
        return f"<{n} chars>"
    if n < 16:
        return f"{s[:2]}…{s[-2:]} ({n} chars)"
    return f"{s[:4]}…{s[-4:]} ({n} chars)"


def _digest(secret: str) -> str:
    mac = hmac.new(
        _secret_key(), secret.strip().encode("utf-8", "replace"), hashlib.sha256
    )
    return "sha256:" + mac.hexdigest()


# ---- detectors ------------------------------------------------------------
#
# Patterns are intentionally specific — a credential detector that fires on
# every hex string is worse than useless, because it buries the real leaks.

_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"
    r".*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
    re.DOTALL,
)

# High-confidence provider token formats. These prefixes are provider-assigned,
# so a match is a real token shape, not a coincidence.
_TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\b(A(?:KIA|SIA|GPA|IDA|ROA|IPA|NPA|NVA)[0-9A-Z]{16})\b")),
    ("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("slack_token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b")),
    ("github_pat", re.compile(r"\b(ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{22,})\b")),
    ("stripe_secret_key", re.compile(r"\b(sk_live_[0-9A-Za-z]{24,})\b")),
    ("openai_key", re.compile(r"\b(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b")),
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")),
    ("twilio_key", re.compile(r"\b(SK[0-9a-fA-F]{32})\b")),
    ("sendgrid_key", re.compile(r"\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b")),
]

# key = value assignments where the key name signals a secret. The value must be
# non-trivial and not an obvious placeholder.
_ASSIGNMENT = re.compile(
    r"(?i)([A-Za-z0-9]*(?:password|passwd|secret|api[_-]?key|apikey|"
    r"access[_-]?token|auth[_-]?token|client[_-]?secret|db[_-]?pass)[A-Za-z0-9]*)"
    r"\s*[:=]\s*[\"']?([^\s\"'<>&]{6,80})[\"']?"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:x{3,}|\*{3,}|\.{3,}|your[_-]?|example|changeme|placeholder|"
    r"none|null|true|false|test|password|secret|redacted|\$\{|\{\{|<)"
)

# email:password dump lines (the classic combolist shape).
_CRED_PAIR = re.compile(
    r"\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}):([^\s:,;<>\"']{4,64})"
)


@dataclass(frozen=True)
class _Span:
    """One detected secret, with the exact character range to redact.

    ``redact_start``/``redact_end`` cover only the secret itself — for a
    credential pair the account (email) is left visible and only the password is
    blanked, because the account is itself a useful, non-secret identifier.
    """

    type: str
    label: str
    secret: str          # what gets hashed
    redact_start: int
    redact_end: int


def _find_spans(text: str) -> list[_Span]:
    """Locate every credential-shaped secret and the range that should be hidden."""
    spans: list[_Span] = []

    for m in _PRIVATE_KEY.finditer(text):
        spans.append(_Span(SECRET_PRIVATE_KEY, "private key", m.group(0),
                           m.start(), m.end()))

    for label, pattern in _TOKEN_PATTERNS:
        for m in pattern.finditer(text):
            spans.append(_Span(SECRET_API_TOKEN, label, m.group(1),
                               m.start(1), m.end(1)))

    for m in _ASSIGNMENT.finditer(text):
        key, value = m.group(1), m.group(2)
        if _PLACEHOLDER.match(value):
            continue
        spans.append(_Span(SECRET_ASSIGNMENT, f"{key.lower()} value", value,
                           m.start(2), m.end(2)))

    for m in _CRED_PAIR.finditer(text):
        account, secret = m.group(1), m.group(2)
        if _PLACEHOLDER.match(secret):
            continue
        # Hash the whole pair (that is what dedupes a combolist entry), but only
        # redact the password half — the account stays legible.
        spans.append(_Span(CREDENTIAL_PAIR, f"pair {account}",
                           f"{account}:{secret}", m.start(2), m.end(2)))

    return spans


def _identifier_for(span: _Span, where: str, seen: set[str]) -> Identifier | None:
    """Build the flagged, hashed Identifier for one span (dedup by digest)."""
    digest = _digest(span.secret)
    if digest in seen:
        return None
    seen.add(digest)

    if span.type == CREDENTIAL_PAIR:
        account = span.secret.split(":", 1)[0]
        password = span.secret.split(":", 1)[1] if ":" in span.secret else ""
        context = (f"LEAKED credential pair: {account}:{mask(password)}{where} "
                   f"— passively observed; likely a dump/combolist entry")
    else:
        context = (f"LEAKED {span.label}: {mask(span.secret)}{where} "
                   f"— passively observed in collected content; verify before acting")
    return Identifier(span.type, digest, context=context, heuristic=True)


def extract_secrets(text: str, url: str = "") -> list[Identifier]:
    """Detect credential-shaped secrets in already-collected ``text``.

    Returns flagged identifiers whose ``value`` is a keyed hash (never the
    plaintext) and whose ``context`` is a masked preview plus provenance.
    """
    out: list[Identifier] = []
    if not text:
        return out
    where = f" — seen on {url}" if url else ""
    seen: set[str] = set()
    for span in _find_spans(text):
        ident = _identifier_for(span, where, seen)
        if ident is not None:
            out.append(ident)
    return out


def redact_secrets(text: str, url: str = "") -> tuple[str, list[Identifier]]:
    """Detect secrets and return ``(redacted_text, identifiers)``.

    Every secret span in ``redacted_text`` is replaced by a short placeholder
    carrying the digest prefix, so a caller that stores this text (page
    documents, identifier context windows) never persists the plaintext. The
    caller keeps the untouched original only in the raw on-disk snapshot.
    """
    if not text:
        return text, []

    where = f" — seen on {url}" if url else ""
    seen: set[str] = set()
    identifiers: list[Identifier] = []

    spans = _find_spans(text)
    # Build identifiers first (dedup by digest, same ordering as extract_secrets).
    for span in spans:
        ident = _identifier_for(span, where, seen)
        if ident is not None:
            identifiers.append(ident)

    # Redact from the end backwards so earlier offsets stay valid. Drop spans
    # that overlap one already applied (e.g. an assignment value inside a key
    # block), keeping the earliest/outermost.
    ordered = sorted(spans, key=lambda s: (s.redact_start, -(s.redact_end)))
    applied: list[tuple[int, int]] = []
    kept: list[_Span] = []
    for span in ordered:
        if any(span.redact_start < e and span.redact_end > s for s, e in applied):
            continue
        applied.append((span.redact_start, span.redact_end))
        kept.append(span)

    redacted = text
    for span in sorted(kept, key=lambda s: -s.redact_start):
        digest8 = _digest(span.secret).split(":", 1)[1][:8]
        placeholder = REDACTION_TEMPLATE.format(label=span.type, digest8=digest8)
        redacted = redacted[: span.redact_start] + placeholder + redacted[span.redact_end:]

    return redacted, identifiers
