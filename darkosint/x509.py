"""Minimal DER / X.509 certificate parser — dependency-free.

Why this exists: a Tor hidden service's TLS certificate is the single richest
misconfiguration artifact available passively. Operators routinely reuse the
certificate — or, more tellingly, the *key pair* — from their clearnet origin
server, leaving the clearnet domain sitting in the certificate's Common Name or
Subject Alternative Name.

Python's :mod:`ssl` module will only hand back a parsed certificate dict when it
has *verified* the peer. Onion service certificates are self-signed, so
verification must be disabled, and at that point ``getpeercert()`` returns an
empty dict and only ``getpeercert(binary_form=True)`` (raw DER) is available.
Hence this parser.

It extracts the fields that matter for infrastructure correlation:

  * ``subject_cn`` / ``san_dns``      — clearnet domains named by the cert
  * ``sha256``                        — cert identity, for exact cross-host match
  * ``spki_sha256``                   — the *public key* hash: survives certificate
                                        reissue, so it links an onion service to a
                                        clearnet host that merely renewed its cert
  * ``issuer_cn``, ``serial``, validity, and self-signed status

Parsing is deliberately tolerant: a malformed or truncated certificate yields
whatever was recoverable rather than raising, because a partially-read cert that
still surrenders a SAN entry is operationally valuable.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# ASN.1 DER
# ---------------------------------------------------------------------------

CLASS_UNIVERSAL = 0x00
CLASS_CONTEXT = 0x80
CONSTRUCTED = 0x20

TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_SEQUENCE = 0x10
TAG_SET = 0x11
TAG_PRINTABLE_STRING = 0x13
TAG_IA5_STRING = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18
TAG_BMP_STRING = 0x1E

_STRING_TAGS = {
    TAG_UTF8_STRING,
    TAG_PRINTABLE_STRING,
    TAG_IA5_STRING,
    0x12,  # NumericString
    0x14,  # TeletexString / T61String
    0x15,  # VideotexString
    0x1A,  # VisibleString / ISO646String
    0x1B,  # GeneralString
    TAG_BMP_STRING,
}


class DerError(ValueError):
    """Raised when a DER structure cannot be read at all."""


@dataclass(frozen=True)
class Tlv:
    """One decoded DER tag-length-value triple."""

    tag: int          # full first octet (class | constructed | number)
    value: bytes
    end: int          # offset just past this TLV in the parent buffer

    @property
    def number(self) -> int:
        """The tag number, with class and constructed bits masked off."""
        return self.tag & 0x1F

    @property
    def is_constructed(self) -> bool:
        return bool(self.tag & CONSTRUCTED)

    @property
    def is_context(self) -> bool:
        return (self.tag & 0xC0) == CLASS_CONTEXT


def read_tlv(data: bytes, offset: int = 0) -> Tlv:
    """Read one TLV starting at ``offset``."""
    if offset >= len(data):
        raise DerError("read past end of buffer")
    tag = data[offset]
    i = offset + 1
    if tag & 0x1F == 0x1F:  # multi-octet tag number
        while i < len(data) and data[i] & 0x80:
            i += 1
        i += 1
    if i >= len(data):
        raise DerError("truncated length")
    first = data[i]
    i += 1
    if first & 0x80:
        n = first & 0x7F
        if n == 0:
            raise DerError("indefinite lengths are not valid in DER")
        if i + n > len(data):
            raise DerError("truncated long-form length")
        length = int.from_bytes(data[i:i + n], "big")
        i += n
    else:
        length = first
    end = i + length
    if end > len(data):
        # Tolerate truncation: hand back what is actually present.
        end = len(data)
    return Tlv(tag=tag, value=data[i:end], end=end)


def read_sequence(data: bytes) -> list[Tlv]:
    """Read every TLV in a constructed value, left to right."""
    out: list[Tlv] = []
    offset = 0
    while offset < len(data):
        try:
            tlv = read_tlv(data, offset)
        except DerError:
            break
        out.append(tlv)
        if tlv.end <= offset:  # zero-length guard: never spin
            break
        offset = tlv.end
    return out


def decode_oid(value: bytes) -> str:
    """Decode an OBJECT IDENTIFIER to dotted-decimal form."""
    if not value:
        return ""
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    acc = 0
    for byte in value[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(acc))
            acc = 0
    return ".".join(parts)


def decode_string(tlv: Tlv) -> str:
    """Decode a DER string value, honouring the handful of encodings in use."""
    if tlv.number == TAG_BMP_STRING:
        return tlv.value.decode("utf-16-be", errors="replace")
    return tlv.value.decode("utf-8", errors="replace")


def decode_time(tlv: Tlv) -> str | None:
    """Decode UTCTime / GeneralizedTime to an ISO-8601 UTC string.

    The year field width is fixed by the tag, not guessed: UTCTime is
    ``YYMMDDHHMMSSZ`` (two-digit year, pivoted at 50 per RFC 5280 §4.1.2.5.1)
    and GeneralizedTime is ``YYYYMMDDHHMMSSZ``.
    """
    raw = tlv.value.decode("ascii", errors="replace").strip()
    year_digits = 2 if tlv.number == TAG_UTC_TIME else 4
    m = re.match(
        r"^(\d{%d})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?" % year_digits, raw
    )
    if not m:
        return None
    year = int(m.group(1))
    if tlv.number == TAG_UTC_TIME:
        year += 2000 if year < 50 else 1900
    try:
        dt = datetime(
            year, int(m.group(2)), int(m.group(3)),
            int(m.group(4)), int(m.group(5)), int(m.group(6) or 0),
            tzinfo=timezone.utc,
        )
    except ValueError:
        return None
    return dt.isoformat()


# ---------------------------------------------------------------------------
# X.509
# ---------------------------------------------------------------------------

OID_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
}

OID_SAN = "2.5.29.17"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1"

# GeneralName context tag numbers (RFC 5280 §4.2.1.6).
GN_RFC822 = 1
GN_DNS = 2
GN_URI = 6
GN_IP = 7


@dataclass
class Certificate:
    """The subset of an X.509 certificate that matters for correlation."""

    sha256: str = ""
    spki_sha256: str = ""
    serial: str = ""
    version: int = 1
    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    not_before: str | None = None
    not_after: str | None = None
    san_dns: list[str] = field(default_factory=list)
    san_ip: list[str] = field(default_factory=list)
    san_email: list[str] = field(default_factory=list)
    san_uri: list[str] = field(default_factory=list)
    signature_algorithm: str = ""
    parse_errors: list[str] = field(default_factory=list)

    @property
    def subject_cn(self) -> str:
        return self.subject.get("CN", "")

    @property
    def issuer_cn(self) -> str:
        return self.issuer.get("CN", "")

    @property
    def self_signed(self) -> bool:
        return bool(self.subject) and self.subject == self.issuer

    def dns_names(self) -> list[str]:
        """Every DNS name the certificate asserts (CN + SAN), deduplicated."""
        names: list[str] = []
        for candidate in [self.subject_cn, *self.san_dns]:
            c = candidate.strip().lower().rstrip(".")
            if c and c not in names:
                names.append(c)
        return names

    def clearnet_names(self) -> list[str]:
        """DNS names that are NOT .onion — i.e. direct clearnet attribution."""
        return [n for n in self.dns_names() if not n.endswith(".onion")]


def _parse_name(value: bytes) -> dict[str, str]:
    """Decode an X.501 Name (SEQUENCE OF SET OF AttributeTypeAndValue)."""
    out: dict[str, str] = {}
    for rdn in read_sequence(value):
        if not rdn.is_constructed:
            continue
        for atv in read_sequence(rdn.value):
            parts = read_sequence(atv.value)
            if len(parts) < 2 or parts[0].number != TAG_OID:
                continue
            oid = decode_oid(parts[0].value)
            key = OID_NAMES.get(oid, oid)
            if parts[1].number in _STRING_TAGS:
                text = decode_string(parts[1])
            else:
                text = parts[1].value.decode("utf-8", errors="replace")
            # Multi-valued RDNs are rare; keep the first, note the rest.
            if key in out:
                out[key] = f"{out[key]},{text}"
            else:
                out[key] = text
    return out


def _format_ip(raw: bytes) -> str:
    if len(raw) == 4:
        return ".".join(str(b) for b in raw)
    if len(raw) == 16:
        return ":".join(raw[i:i + 2].hex() for i in range(0, 16, 2))
    return raw.hex()


def _parse_san(extn_value: bytes, cert: Certificate) -> None:
    """Decode a SubjectAltName extension into the certificate's SAN lists."""
    try:
        inner = read_tlv(extn_value)          # the OCTET STRING wrapper
        names = read_tlv(inner.value)         # GeneralNames SEQUENCE
    except DerError as exc:
        cert.parse_errors.append(f"san: {exc}")
        return
    for gn in read_sequence(names.value):
        if not gn.is_context:
            continue
        num = gn.number
        if num == GN_DNS:
            cert.san_dns.append(gn.value.decode("utf-8", errors="replace"))
        elif num == GN_IP:
            cert.san_ip.append(_format_ip(gn.value))
        elif num == GN_RFC822:
            cert.san_email.append(gn.value.decode("utf-8", errors="replace"))
        elif num == GN_URI:
            cert.san_uri.append(gn.value.decode("utf-8", errors="replace"))


def parse_der(der: bytes) -> Certificate:
    """Parse a DER-encoded X.509 certificate.

    Never raises for a merely malformed certificate: whatever could be decoded is
    returned, with the failures recorded in ``parse_errors``.
    """
    cert = Certificate()
    if not der:
        cert.parse_errors.append("empty certificate")
        return cert

    cert.sha256 = hashlib.sha256(der).hexdigest()

    try:
        outer = read_tlv(der)
        top = read_sequence(outer.value)
    except DerError as exc:
        cert.parse_errors.append(f"outer: {exc}")
        return cert
    if not top:
        cert.parse_errors.append("no tbsCertificate")
        return cert

    tbs_fields = read_sequence(top[0].value)
    idx = 0

    # Optional [0] EXPLICIT version.
    if tbs_fields and tbs_fields[0].is_context and tbs_fields[0].number == 0:
        try:
            v = read_tlv(tbs_fields[0].value)
            cert.version = int.from_bytes(v.value, "big") + 1
        except DerError:
            pass
        idx = 1

    def field_at(i: int) -> Tlv | None:
        return tbs_fields[i] if i < len(tbs_fields) else None

    serial = field_at(idx)
    if serial is not None:
        cert.serial = serial.value.hex().upper().lstrip("0") or "0"

    sig_alg = field_at(idx + 1)
    if sig_alg is not None:
        parts = read_sequence(sig_alg.value)
        if parts and parts[0].number == TAG_OID:
            cert.signature_algorithm = decode_oid(parts[0].value)

    issuer = field_at(idx + 2)
    if issuer is not None:
        cert.issuer = _parse_name(issuer.value)

    validity = field_at(idx + 3)
    if validity is not None:
        times = read_sequence(validity.value)
        if len(times) >= 1:
            cert.not_before = decode_time(times[0])
        if len(times) >= 2:
            cert.not_after = decode_time(times[1])

    subject = field_at(idx + 4)
    if subject is not None:
        cert.subject = _parse_name(subject.value)

    spki = field_at(idx + 5)
    if spki is not None:
        # Hash the whole SubjectPublicKeyInfo, re-encoded with its own header, so
        # the digest matches the conventional "SPKI pin" other tooling computes.
        cert.spki_sha256 = hashlib.sha256(
            _reencode(spki)
        ).hexdigest()

    # Extensions live in the optional [3] EXPLICIT field at the end.
    for tlv in tbs_fields[idx + 6:]:
        if not (tlv.is_context and tlv.number == 3):
            continue
        try:
            ext_seq = read_tlv(tlv.value)
        except DerError as exc:
            cert.parse_errors.append(f"extensions: {exc}")
            break
        for ext in read_sequence(ext_seq.value):
            parts = read_sequence(ext.value)
            if not parts or parts[0].number != TAG_OID:
                continue
            oid = decode_oid(parts[0].value)
            payload = parts[-1]
            if oid == OID_SAN:
                _parse_san(_reencode(payload), cert)

    return cert


def _reencode(tlv: Tlv) -> bytes:
    """Re-serialize a TLV (tag + DER length + value) from its decoded form."""
    value = tlv.value
    length = len(value)
    if length < 0x80:
        header = bytes([tlv.tag, length])
    else:
        n = (length.bit_length() + 7) // 8
        header = bytes([tlv.tag, 0x80 | n]) + length.to_bytes(n, "big")
    return header + value


_PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.DOTALL
)


def parse_pem(pem: str) -> list[Certificate]:
    """Parse every PEM-encoded certificate found in ``pem``."""
    import base64

    out: list[Certificate] = []
    for m in _PEM_RE.finditer(pem or ""):
        b64 = "".join(m.group(1).split())
        try:
            out.append(parse_der(base64.b64decode(b64)))
        except Exception:  # noqa: BLE001 - a bad block must not sink the rest
            continue
    return out
