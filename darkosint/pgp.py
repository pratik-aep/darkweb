"""OpenPGP public key parsing — dependency-free.

The single highest-value de-anonymization artifact on a marketplace or forum is
often the *User ID packet* inside an armored PGP public key: vendors routinely
paste a key whose UID still carries a real name, a personal email, or a handle
they use elsewhere. Hashing the armored block (as a content address) throws all
of that away, so this module parses the key properly:

  armored text -> CRC24-checked base64 -> OpenPGP packet stream
               -> Public-Key packet  -> v4/v5/v6 fingerprint + key ID
               -> User ID packets     -> names / emails / handles
               -> Public-Subkey packets (recorded, for subkey pivoting)

The **fingerprint** is the correct cross-source join key: the same actor
re-publishing their key on another market produces a byte-identical
fingerprint even when the armor, comments, and surrounding HTML differ.

Everything here is pure `bytes -> structure`; nothing touches the network or
the disk, which keeps it offline-testable. Implemented against RFC 4880 (v4),
RFC 4880bis (v5) and RFC 9580 (v6).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# armor handling
# ---------------------------------------------------------------------------

_ARMOR_RE = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)

# Public-key algorithm IDs (RFC 4880 §9.1 + RFC 9580).
ALGORITHMS = {
    1: "RSA",
    2: "RSA-encrypt-only",
    3: "RSA-sign-only",
    16: "ElGamal",
    17: "DSA",
    18: "ECDH",
    19: "ECDSA",
    22: "EdDSA-legacy",
    25: "X25519",
    26: "X448",
    27: "Ed25519",
    28: "Ed448",
}


class PgpParseError(ValueError):
    """Raised when armored text or a packet stream cannot be parsed."""


def crc24(data: bytes) -> int:
    """OpenPGP CRC-24 (RFC 4880 §6.1) over the raw packet bytes."""
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def find_armored_blocks(text: str) -> list[str]:
    """Return every armored public key block present in ``text``."""
    return [m.group(0) for m in _ARMOR_RE.finditer(text or "")]


def dearmor(block: str) -> tuple[bytes, bool]:
    """Decode an armored block to raw packet bytes.

    Returns ``(packet_bytes, checksum_ok)``. A block scraped out of HTML is
    frequently mangled (``<br>`` tags, entities, soft wrapping), so the armor is
    normalized first and a failed CRC is reported rather than raised — a key
    whose checksum does not verify is still worth extracting UIDs from, it just
    carries less confidence.
    """
    m = _ARMOR_RE.search(block)
    body = m.group(1) if m else block

    # Undo the usual HTML mangling before touching the base64.
    body = re.sub(r"(?i)<br\s*/?>", "\n", body)
    body = re.sub(r"(?i)</?(p|div|span|pre|code)[^>]*>", "\n", body)
    body = body.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")

    lines = [ln.strip() for ln in body.splitlines()]
    # Drop the blank line(s) immediately following the BEGIN marker, so the
    # armor-header separator below is not confused with them.
    while lines and not lines[0]:
        lines.pop(0)

    # Armor headers ("Version: ...", "Comment: ...") run until the first blank
    # line. If no blank line survived the mangling, drop any "Key: value" lines.
    if "" in lines:
        lines = lines[lines.index("") + 1:]
    else:
        lines = [ln for ln in lines if not re.match(r"^[A-Za-z][A-Za-z-]*:\s", ln)]

    checksum_line = None
    data_lines: list[str] = []
    for ln in lines:
        if not ln:
            continue
        if ln.startswith("="):
            checksum_line = ln[1:].strip()
            break
        data_lines.append(ln)

    b64 = "".join(data_lines)
    # Scraped armor is often re-wrapped or truncated and loses its "=" padding;
    # restore it rather than discarding an otherwise parseable key.
    if len(b64) % 4:
        b64 += "=" * (4 - len(b64) % 4)
    try:
        raw = base64.b64decode(b64, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise PgpParseError(f"undecodable armor base64: {exc}") from exc
    if not raw:
        raise PgpParseError("armor contained no data")

    checksum_ok = True
    if checksum_line:
        try:
            expected = int.from_bytes(base64.b64decode(checksum_line + "=="), "big")
            checksum_ok = (expected & 0xFFFFFF) == crc24(raw)
        except (binascii.Error, ValueError):
            checksum_ok = False
    return raw, checksum_ok


# ---------------------------------------------------------------------------
# packet stream
# ---------------------------------------------------------------------------

TAG_SIGNATURE = 2
TAG_PUBLIC_KEY = 6
TAG_USER_ID = 13
TAG_PUBLIC_SUBKEY = 14
TAG_USER_ATTRIBUTE = 17


@dataclass(frozen=True)
class Packet:
    tag: int
    body: bytes


def iter_packets(data: bytes) -> list[Packet]:
    """Split an OpenPGP packet stream into packets (old and new length formats)."""
    packets: list[Packet] = []
    i = 0
    n = len(data)
    while i < n:
        first = data[i]
        if not first & 0x80:
            raise PgpParseError(f"invalid packet header 0x{first:02x} at offset {i}")
        i += 1
        if first & 0x40:  # new format
            tag = first & 0x3F
            if i >= n:
                break
            l0 = data[i]
            i += 1
            if l0 < 192:
                length = l0
            elif l0 < 224:
                if i >= n:
                    break
                length = ((l0 - 192) << 8) + data[i] + 192
                i += 1
            elif l0 == 255:
                if i + 4 > n:
                    break
                length = int.from_bytes(data[i:i + 4], "big")
                i += 4
            else:
                # Partial body lengths only occur on streamed literal data, never
                # in a transferable public key; stop rather than misparse.
                break
        else:  # old format
            tag = (first >> 2) & 0x0F
            length_type = first & 0x03
            if length_type == 0:
                if i >= n:
                    break
                length, i = data[i], i + 1
            elif length_type == 1:
                if i + 2 > n:
                    break
                length, i = int.from_bytes(data[i:i + 2], "big"), i + 2
            elif length_type == 2:
                if i + 4 > n:
                    break
                length, i = int.from_bytes(data[i:i + 4], "big"), i + 4
            else:
                length = n - i  # indeterminate: runs to end of stream

        if length < 0 or i + length > n:
            length = n - i  # tolerate truncation rather than dropping the key
        packets.append(Packet(tag=tag, body=data[i:i + length]))
        i += length
    return packets


# ---------------------------------------------------------------------------
# key material
# ---------------------------------------------------------------------------


def key_fingerprint(body: bytes) -> tuple[str, int, int | None, str]:
    """Fingerprint a Public-Key/Public-Subkey packet body.

    Returns ``(fingerprint_hex_upper, version, created_unix, algorithm_name)``.
    The hash preimage differs per version (RFC 4880 §12.2, RFC 9580 §5.5.4):
      v4 -> SHA-1  over 0x99 || uint16 len || body
      v5 -> SHA-256 over 0x9A || uint32 len || body
      v6 -> SHA-256 over 0x9B || uint32 len || body
    """
    if not body:
        raise PgpParseError("empty key packet")
    version = body[0]

    if version == 4:
        preimage = b"\x99" + len(body).to_bytes(2, "big") + body
        fpr = hashlib.sha1(preimage).hexdigest().upper()
    elif version in (5, 6):
        marker = b"\x9a" if version == 5 else b"\x9b"
        preimage = marker + len(body).to_bytes(4, "big") + body
        fpr = hashlib.sha256(preimage).hexdigest().upper()
    elif version in (2, 3):
        # v3 fingerprints are MD5 over the RSA modulus+exponent only; these keys
        # are long obsolete, so record the version and skip the fingerprint.
        raise PgpParseError(f"unsupported legacy key version {version}")
    else:
        raise PgpParseError(f"unknown key packet version {version}")

    created = None
    algo_id = None
    if len(body) >= 6:
        created = int.from_bytes(body[1:5], "big")
        algo_id = body[5]
    algo = ALGORITHMS.get(algo_id or -1, f"algo-{algo_id}")
    return fpr, version, created, algo


def key_id_from_fingerprint(fpr: str, version: int) -> str:
    """The 64-bit key ID: v4 = last 16 hex of the fingerprint, v6 = first 16."""
    return fpr[-16:] if version == 4 else fpr[:16]


_UID_RE = re.compile(r"^(?P<name>[^(<]*?)\s*(?:\((?P<comment>[^)]*)\))?\s*(?:<(?P<email>[^>]*)>)?\s*$")


@dataclass(frozen=True)
class UserId:
    """One User ID packet, split into its conventional name/comment/email parts."""

    raw: str
    name: str = ""
    comment: str = ""
    email: str = ""

    @classmethod
    def parse(cls, raw: str) -> "UserId":
        m = _UID_RE.match(raw.strip())
        if not m:
            return cls(raw=raw)
        return cls(
            raw=raw,
            name=(m.group("name") or "").strip(),
            comment=(m.group("comment") or "").strip(),
            email=(m.group("email") or "").strip(),
        )


@dataclass
class PgpKey:
    """A parsed transferable public key."""

    fingerprint: str
    key_id: str
    version: int
    algorithm: str
    created: int | None
    uids: list[UserId] = field(default_factory=list)
    subkey_fingerprints: list[str] = field(default_factory=list)
    checksum_ok: bool = True
    armored: str = ""

    @property
    def emails(self) -> list[str]:
        return [u.email for u in self.uids if u.email]

    @property
    def names(self) -> list[str]:
        return [u.name for u in self.uids if u.name]

    @property
    def fingerprint_spaced(self) -> str:
        """The conventional ``XXXX XXXX ...`` display grouping."""
        return " ".join(
            self.fingerprint[i:i + 4] for i in range(0, len(self.fingerprint), 4)
        )


def parse_key(armored: str) -> PgpKey:
    """Parse one armored public key block into a :class:`PgpKey`."""
    raw, checksum_ok = dearmor(armored)
    packets = iter_packets(raw)

    primary: PgpKey | None = None
    for pkt in packets:
        if pkt.tag == TAG_PUBLIC_KEY and primary is None:
            fpr, version, created, algo = key_fingerprint(pkt.body)
            primary = PgpKey(
                fingerprint=fpr,
                key_id=key_id_from_fingerprint(fpr, version),
                version=version,
                algorithm=algo,
                created=created,
                checksum_ok=checksum_ok,
                armored=armored,
            )
        elif pkt.tag == TAG_USER_ID and primary is not None:
            primary.uids.append(
                UserId.parse(pkt.body.decode("utf-8", errors="replace"))
            )
        elif pkt.tag == TAG_PUBLIC_SUBKEY and primary is not None:
            try:
                sub_fpr, _, _, _ = key_fingerprint(pkt.body)
            except PgpParseError:
                continue
            primary.subkey_fingerprints.append(sub_fpr)

    if primary is None:
        raise PgpParseError("no public key packet found in block")
    return primary


def parse_all(text: str) -> list[PgpKey]:
    """Parse every armored public key block found in ``text``, skipping bad ones."""
    keys: list[PgpKey] = []
    for block in find_armored_blocks(text):
        try:
            keys.append(parse_key(block))
        except (PgpParseError, ValueError, IndexError):
            continue  # a mangled block is not worth failing the whole page over
    return keys
