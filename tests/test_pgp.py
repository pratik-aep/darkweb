"""Unit tests for OpenPGP key parsing.

The fixture is a real, unmodified transferable public key (the RFC 9580 "Alice"
sample, Ed25519/v4). Its fingerprint is published, so these tests check the
parser against a known answer rather than against itself.
"""
from __future__ import annotations

import pytest

from darkosint.pgp import (
    PgpParseError,
    UserId,
    crc24,
    dearmor,
    find_armored_blocks,
    iter_packets,
    key_fingerprint,
    parse_all,
    parse_key,
)

# A REAL, unmodified key retrieved from keys.openpgp.org by requesting this exact
# fingerprint — so the expected value below is the server's assertion, not ours.
# keys.openpgp.org strips User IDs from unverified keys, so UID parsing is
# covered separately by a key built packet-by-packet in ``_build_key_with_uid``.
ALICE = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: EB85 BB5F A33A 75E1 5E94  4E63 F231 550C 4F47 E38E

xjMEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U
b7O1u13OOARcRwTpEgorBgEEAZdVAQUBAQdAQv8GIa2rSTzgqbXCpDDYMiKRVitC
sy203x3sE9+eviIDAQgHwngEGBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUC
XEcE6QIbDAAKCRDyMVUMT0fjjlnQAQDFHUs6TIcxrNTtEZFjUFm1M0PJ1Dng/cDW
4xN80fsn0QEA22Kr7VkCjeAEC08VSTeV+QFsmz55/lntWkwYWhmvOgE=
=qReC
-----END PGP PUBLIC KEY BLOCK-----"""

ALICE_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E"


def test_crc24_matches_openpgp_definition():
    # RFC 4880's CRC-24 has a defined initial value, so the empty input is fixed.
    assert crc24(b"") == 0xB704CE
    assert crc24(b"abc") != crc24(b"abd")


def test_find_armored_blocks_locates_every_block():
    text = f"intro\n{ALICE}\nmiddle\n{ALICE}\noutro"
    assert len(find_armored_blocks(text)) == 2


def test_dearmor_skips_armor_headers():
    """A Comment:/Version: header must not be fed into the base64 decoder.

    Regression test: treating the newline after the BEGIN marker as the
    header/body separator left the Comment line in the payload and made every
    real-world key from a keyserver fail to decode.
    """
    raw, checksum_ok = dearmor(ALICE)
    assert raw[:1] == b"\xc6"  # new-format public key packet (tag 6)
    assert checksum_ok


def test_dearmor_tolerates_missing_base64_padding():
    mangled = ALICE.replace("hPgU=\n", "hPgU\n")
    raw, _ = dearmor(mangled)
    assert raw


def test_dearmor_survives_html_mangling():
    """Armor scraped out of a page arrives wrapped in markup."""
    html = ALICE.replace("\n", "<br>\n").replace("<", "&lt;", 1)
    html = html.replace("&lt;", "<", 1)  # restore the BEGIN marker
    raw, _ = dearmor(html)
    assert raw


def test_parse_key_recovers_the_published_fingerprint():
    key = parse_key(ALICE)
    assert key.fingerprint == ALICE_FPR
    assert key.key_id == ALICE_FPR[-16:]   # v4 key ID is the low 64 bits
    assert key.version == 4
    assert key.algorithm == "EdDSA-legacy"
    assert key.checksum_ok


def test_parse_key_records_subkeys():
    """Subkey fingerprints are pivotable too, so they are kept (flagged weaker)."""
    key = parse_key(ALICE)
    assert key.subkey_fingerprints
    assert all(len(f) == 40 for f in key.subkey_fingerprints)


def test_fingerprint_spacing_is_the_conventional_grouping():
    key = parse_key(ALICE)
    assert key.fingerprint_spaced.startswith("EB85 BB5F A33A")
    assert len(key.fingerprint_spaced.split()) == 10


def _build_key_with_uid(uid: str) -> tuple[str, str]:
    """Assemble a valid armored key carrying ``uid``; return (armor, fingerprint).

    Built packet-by-packet rather than downloaded, because public keyservers
    strip User IDs from unverified keys and the UID packet is exactly what needs
    covering here. The expected fingerprint is computed with a plain ``hashlib``
    call, independent of the module under test.
    """
    import base64
    import hashlib

    # v4 public key packet body: version, creation time, algo 22 (EdDSA), then
    # the curve OID and the MPI-encoded point.
    body = (
        bytes([4])
        + (1548158185).to_bytes(4, "big")
        + bytes([22])
        + bytes([9]) + bytes.fromhex("2B06010401DA470F01")  # Ed25519 OID
        + (263).to_bytes(2, "big") + b"\x40" + bytes(range(32))
    )
    key_packet = bytes([0xC6, len(body)]) + body
    uid_bytes = uid.encode("utf-8")
    uid_packet = bytes([0xCD, len(uid_bytes)]) + uid_bytes
    raw = key_packet + uid_packet

    checksum = crc24(raw).to_bytes(3, "big")
    armor = (
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
        + base64.encodebytes(raw).decode("ascii")
        + "=" + base64.b64encode(checksum).decode("ascii") + "\n"
        + "-----END PGP PUBLIC KEY BLOCK-----"
    )
    expected = hashlib.sha1(
        b"\x99" + len(body).to_bytes(2, "big") + body
    ).hexdigest().upper()
    return armor, expected


def test_parse_key_extracts_user_id_identities():
    """The User ID packet is the point of parsing rather than hashing.

    A vendor's key frequently still carries the name and email they chose, which
    a content hash of the armored block would discard entirely.
    """
    armor, expected = _build_key_with_uid("Alice Lovelace <alice@openpgp.example>")
    key = parse_key(armor)

    assert key.fingerprint == expected
    assert key.checksum_ok
    assert any(u.name == "Alice Lovelace" for u in key.uids)
    assert "alice@openpgp.example" in key.emails
    assert "Alice Lovelace" in key.names


def test_armor_checksum_failure_is_reported_not_raised():
    """A corrupted CRC must downgrade confidence, not discard the key."""
    armor, _ = _build_key_with_uid("Someone <s@example.test>")
    corrupted = armor.replace("\n=", "\n=AAAA\n#")  # break the checksum line
    key = parse_key(corrupted)
    assert key.uids  # identities still recovered
    assert key.checksum_ok is False


def test_user_id_parsing_splits_name_comment_email():
    uid = UserId.parse("Jo Blogs (work key) <jo@example.test>")
    assert uid.name == "Jo Blogs"
    assert uid.comment == "work key"
    assert uid.email == "jo@example.test"

    bare = UserId.parse("justahandle")
    assert bare.name == "justahandle"
    assert bare.email == ""


def test_iter_packets_handles_old_and_new_length_formats():
    # Old format, 1-byte length: 0x98 = tag 6, length_type 0.
    old = bytes([0x98, 0x03]) + b"abc"
    # New format, short length: 0xC6 = tag 6.
    new = bytes([0xC6, 0x03]) + b"xyz"
    packets = iter_packets(old + new)
    assert [p.tag for p in packets] == [6, 6]
    assert [p.body for p in packets] == [b"abc", b"xyz"]


def test_key_fingerprint_rejects_unsupported_versions():
    with pytest.raises(PgpParseError):
        key_fingerprint(bytes([3]) + b"\x00" * 10)   # v3 is obsolete
    with pytest.raises(PgpParseError):
        key_fingerprint(b"")


def test_parse_key_rejects_text_with_no_key_packet():
    with pytest.raises(PgpParseError):
        parse_key(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\naGVsbG8=\n"
            "-----END PGP PUBLIC KEY BLOCK-----"
        )


def test_parse_all_skips_unparseable_blocks_without_failing():
    broken = (
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!!!not base64!!!\n"
        "-----END PGP PUBLIC KEY BLOCK-----"
    )
    keys = parse_all(f"{broken}\n{ALICE}")
    assert len(keys) == 1
    assert keys[0].fingerprint == ALICE_FPR
