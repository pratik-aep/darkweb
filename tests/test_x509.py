"""Unit tests for the DER / X.509 parser and infrastructure fingerprints.

The certificate fixture is generated in-process with a fixed structure, so these
tests are deterministic and offline. The parser itself was additionally checked
during development against live certificates from three public hosts, comparing
every field against Python's own verified ``getpeercert()`` output.
"""
from __future__ import annotations

from darkosint.fingerprints import (
    ANALYTICS_ID,
    CLEARNET_DOMAIN,
    ETAG,
    IPV4,
    S3_BUCKET,
    SERVER_BANNER,
    TLS_SPKI,
    certificate_identifiers,
    favicon_hash,
    header_identifiers,
    murmur3_32,
    page_artifacts,
)
from darkosint.x509 import (
    Certificate,
    decode_oid,
    decode_time,
    parse_der,
    parse_pem,
    read_sequence,
    read_tlv,
)

# ---------------------------------------------------------------------------
# DER primitives
# ---------------------------------------------------------------------------


def test_read_tlv_short_and_long_form_lengths():
    short = bytes([0x04, 0x03]) + b"abc"
    assert read_tlv(short).value == b"abc"

    payload = b"x" * 300
    long_form = bytes([0x04, 0x82, 0x01, 0x2C]) + payload
    assert read_tlv(long_form).value == payload


def test_read_tlv_tolerates_truncation():
    """A truncated certificate should still surrender what it contains."""
    truncated = bytes([0x04, 0x10]) + b"only-eight"
    assert read_tlv(truncated).value == b"only-eight"


def test_read_sequence_walks_siblings_and_terminates():
    data = bytes([0x02, 0x01, 0x01]) + bytes([0x02, 0x01, 0x02])
    assert [t.value for t in read_sequence(data)] == [b"\x01", b"\x02"]


def test_decode_oid_dotted_decimal():
    assert decode_oid(bytes.fromhex("551d11")) == "2.5.29.17"        # subjectAltName
    assert decode_oid(bytes.fromhex("550403")) == "2.5.4.3"          # commonName


def test_decode_time_year_width_is_fixed_by_the_tag():
    """Regression: a greedy year match read UTCTime '261129...' as year 2611."""
    utc = read_tlv(bytes([0x17, 0x0D]) + b"261129235959Z")
    assert decode_time(utc) == "2026-11-29T23:59:59+00:00"

    generalized = read_tlv(bytes([0x18, 0x0F]) + b"20261129235959Z")
    assert decode_time(generalized) == "2026-11-29T23:59:59+00:00"

    assert decode_time(read_tlv(bytes([0x17, 0x03]) + b"bad")) is None


# ---------------------------------------------------------------------------
# certificate construction + parsing
# ---------------------------------------------------------------------------

def _tlv(tag: int, value: bytes) -> bytes:
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    n = (len(value).bit_length() + 7) // 8
    return bytes([tag, 0x80 | n]) + len(value).to_bytes(n, "big") + value


def _name(common_name: str) -> bytes:
    atv = _tlv(0x30, _tlv(0x06, bytes.fromhex("550403")) + _tlv(0x0C, common_name.encode()))
    return _tlv(0x30, _tlv(0x31, atv))


def _build_cert(cn: str, sans: list[str], issuer: str = "Test CA") -> bytes:
    san_names = b"".join(_tlv(0x82, s.encode()) for s in sans)  # [2] dNSName
    san_ext = _tlv(
        0x30,
        _tlv(0x06, bytes.fromhex("551d11"))
        + _tlv(0x04, _tlv(0x30, san_names)),
    )
    extensions = _tlv(0xA3, _tlv(0x30, san_ext))

    tbs = _tlv(0x30, b"".join([
        _tlv(0xA0, _tlv(0x02, b"\x02")),                       # version v3
        _tlv(0x02, bytes.fromhex("0F0F0F")),                   # serial
        _tlv(0x30, _tlv(0x06, bytes.fromhex("2A864886F70D01010B"))),  # sha256RSA
        _name(issuer),
        _tlv(0x30, _tlv(0x17, b"260101000000Z") + _tlv(0x17, b"261231235959Z")),
        _name(cn),
        _tlv(0x30, _tlv(0x30, _tlv(0x06, bytes.fromhex("2A8648CE3D0201")))
             + _tlv(0x03, b"\x00" + bytes(range(32)))),        # SubjectPublicKeyInfo
        extensions,
    ]))
    return _tlv(0x30, tbs + _tlv(0x30, b"") + _tlv(0x03, b"\x00"))


def test_parse_der_extracts_subject_issuer_serial_and_validity():
    cert = parse_der(_build_cert("shop.example.test", ["shop.example.test"]))
    assert cert.subject_cn == "shop.example.test"
    assert cert.issuer_cn == "Test CA"
    assert cert.serial == "F0F0F"
    assert cert.version == 3
    assert cert.not_before == "2026-01-01T00:00:00+00:00"
    assert cert.not_after == "2026-12-31T23:59:59+00:00"
    assert not cert.parse_errors


def test_parse_der_extracts_subject_alternative_names():
    cert = parse_der(_build_cert("a.example.test", ["a.example.test", "b.example.test"]))
    assert cert.san_dns == ["a.example.test", "b.example.test"]
    assert "b.example.test" in cert.dns_names()


def test_clearnet_names_excludes_onion_addresses():
    """The whole point: a non-.onion name in the cert is the attribution."""
    cert = parse_der(_build_cert(
        "market.onion", ["market.onion", "origin.example.test"]
    ))
    assert cert.clearnet_names() == ["origin.example.test"]


def test_certificate_hashes_are_stable_and_distinct():
    der = _build_cert("x.example.test", ["x.example.test"])
    a, b = parse_der(der), parse_der(der)
    assert a.sha256 == b.sha256 and len(a.sha256) == 64
    # The SPKI hash is over the public key, not the whole certificate, so a
    # reissued certificate with the same key keeps it.
    assert a.spki_sha256 == b.spki_sha256
    assert a.sha256 != a.spki_sha256


def test_self_signed_detection():
    assert parse_der(_build_cert("me.test", [], issuer="me.test")).self_signed
    assert not parse_der(_build_cert("me.test", [], issuer="Other CA")).self_signed


def test_parse_der_never_raises_on_garbage():
    for payload in (b"", b"\x00", b"\x30\x82\xff\xff", bytes(range(64))):
        result = parse_der(payload)
        assert isinstance(result, Certificate)


def test_parse_pem_round_trips():
    import base64

    der = _build_cert("pem.example.test", ["pem.example.test"])
    b64 = base64.encodebytes(der).decode()
    pem = f"-----BEGIN CERTIFICATE-----\n{b64}-----END CERTIFICATE-----"
    certs = parse_pem(pem)
    assert len(certs) == 1
    assert certs[0].subject_cn == "pem.example.test"


# ---------------------------------------------------------------------------
# fingerprints
# ---------------------------------------------------------------------------

def test_murmur3_matches_published_test_vectors():
    """Shodan indexes favicons under this exact hash, so it must be bit-exact."""
    assert murmur3_32(b"") & 0xFFFFFFFF == 0x00000000
    assert murmur3_32(b"hello") & 0xFFFFFFFF == 0x248BFA47
    assert murmur3_32(b"hello, world") & 0xFFFFFFFF == 0x149BBB7F
    assert (
        murmur3_32(b"The quick brown fox jumps over the lazy dog") & 0xFFFFFFFF
        == 0x2E4FF723
    )


def test_murmur3_returns_signed_values_like_mmh3():
    # mmh3.hash returns a signed 32-bit int; Shodan queries use that form.
    assert -(2 ** 31) <= murmur3_32(b"\xff" * 16) < 2 ** 31


def test_favicon_hash_is_deterministic_and_content_sensitive():
    assert favicon_hash(b"icon-bytes") == favicon_hash(b"icon-bytes")
    assert favicon_hash(b"icon-bytes") != favicon_hash(b"other-bytes")


def test_header_identifiers_capture_banners_and_flag_generic_ones():
    ids = header_identifiers(
        {
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3",
            "ETag": '"5f2a-61b2c3d4"',
            "Set-Cookie": "PHPSESSID=abc123; Path=/",
        },
        "http://x.onion/",
    )
    by_type = {i.type: i for i in ids}
    assert by_type[SERVER_BANNER].value == "Apache/2.4.41 (Ubuntu)"
    assert not by_type[SERVER_BANNER].heuristic      # specific version => usable
    assert by_type[ETAG].value == "5f2a-61b2c3d4"
    assert not by_type[ETAG].heuristic               # inode-style => host-identifying
    # Cookie names are kept; cookie VALUES are session secrets and are not.
    assert any(i.value == "PHPSESSID" for i in ids)
    assert not any("abc123" in i.value for i in ids)


def test_bare_server_banner_is_flagged_as_too_generic():
    ids = header_identifiers({"Server": "nginx"}, "http://x.onion/")
    assert next(i for i in ids if i.type == SERVER_BANNER).heuristic


def test_certificate_identifiers_promote_clearnet_names():
    cert = parse_der(_build_cert("m.onion", ["m.onion", "origin.example.test"]))
    ids = certificate_identifiers(cert, "http://m.onion/")
    types = {i.type for i in ids}
    assert TLS_SPKI in types
    clearnet = [i for i in ids if i.type == CLEARNET_DOMAIN]
    assert [i.value for i in clearnet] == ["origin.example.test"]
    # A cert-sourced clearnet name is a finding, not a guess.
    assert not clearnet[0].heuristic
    assert "CERTIFICATE" in clearnet[0].context.upper()


def test_page_artifacts_extract_operator_scoped_identifiers():
    html = """
    <html><head>
      <script>gtag('config','G-ABCD1234XY');</script>
      <script src="https://cdn.jsdelivr.net/npm/thing.js"></script>
      <img src="https://assets.vendorshop.test/logo.png">
      <img src="https://mybucket.s3.us-east-1.amazonaws.com/x.png">
    </head><body>Backend at 203.0.113.45 and 192.168.1.1</body></html>
    """
    ids = page_artifacts(html, "http://market.onion/")
    values = {(i.type, i.value) for i in ids}
    assert (ANALYTICS_ID, "G-ABCD1234XY") in values
    assert (S3_BUCKET, "mybucket") in values
    assert (CLEARNET_DOMAIN, "assets.vendorshop.test") in values
    # Common CDNs attribute nothing and are excluded as noise.
    assert (CLEARNET_DOMAIN, "cdn.jsdelivr.net") not in values
    # Public IPs are evidence; RFC1918 addresses are host-local noise.
    assert (IPV4, "203.0.113.45") in values
    assert (IPV4, "192.168.1.1") not in values
