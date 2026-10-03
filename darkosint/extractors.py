"""Structured identifier extraction from page text.

Pattern-matches the identifier classes that matter for dark web OSINT:
  * PGP public key blocks (stored by content hash) and PGP fingerprints
  * Cryptocurrency addresses: BTC (base58 + bech32/bech32m), ETH, XMR
  * Email addresses and Jabber/XMPP IDs
  * Other .onion links (for frontier expansion)
  * Candidate usernames/handles (HEURISTIC — for analyst review, not ground truth)

Where cheap and dependency-free validation exists it is applied to suppress
false positives: BTC base58 addresses are checksum-verified (base58check) and
bech32 addresses have their checksum verified. ETH and XMR are shape-validated
only (a full check would need keccak), so they are best treated as candidates.

Nothing here reaches the network or the disk; it is pure text -> identifiers,
which keeps it trivially unit-testable and offline-safe.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

# ---- identifier type constants -------------------------------------------

PGP_BLOCK = "pgp_block"
PGP_FINGERPRINT = "pgp_fingerprint"
PGP_UID_NAME = "pgp_uid_name"
BTC_ADDRESS = "btc_address"
ETH_ADDRESS = "eth_address"
XMR_ADDRESS = "xmr_address"
EMAIL = "email"
XMPP = "xmpp"
ONION_URL = "onion_url"
USERNAME = "username_candidate"


@dataclass(frozen=True)
class Identifier:
    """One extracted identifier plus a short surrounding context snippet.

    ``value`` is deduplicated per source by storage. ``context`` is a short
    excerpt (or, for PGP blocks, the full armored key) to aid analyst review.
    ``heuristic`` marks low-confidence findings that need human confirmation.
    """

    type: str
    value: str
    context: str = ""
    heuristic: bool = False


# ---------------------------------------------------------------------------
# base58check + bech32 validation (dependency-free)
# ---------------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def _b58decode(s: str) -> bytes:
    num = 0
    for ch in s:
        num = num * 58 + _B58_INDEX[ch]  # KeyError => invalid character
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))  # each leading '1' is a leading zero byte
    return b"\x00" * pad + body


def base58check_valid(s: str) -> bool:
    """True if ``s`` is a valid base58check string (BTC legacy/P2SH addresses)."""
    try:
        raw = _b58decode(s)
    except KeyError:
        return False
    if len(raw) < 5:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return digest == checksum


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_valid(addr: str, expected_hrp: str = "bc") -> bool:
    """Verify a bech32/bech32m address checksum and human-readable prefix."""
    addr = addr.lower()
    if any(ord(c) < 33 or ord(c) > 126 for c in addr):
        return False
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        return False
    hrp, data_part = addr[:pos], addr[pos + 1:]
    if hrp != expected_hrp:
        return False
    data: list[int] = []
    for c in data_part:
        if c not in _BECH32_CHARSET:
            return False
        data.append(_BECH32_CHARSET.index(c))
    const = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    return const in (_BECH32_CONST, _BECH32M_CONST)


# ---------------------------------------------------------------------------
# compiled patterns
# ---------------------------------------------------------------------------

_RE_PGP_BLOCK = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)
# Fingerprints: either grouped as 10 blocks of 4 hex, or a contiguous 40-hex run.
_RE_PGP_FPR_GROUPED = re.compile(
    r"\b(?:[0-9A-Fa-f]{4}[ \t]+){9}[0-9A-Fa-f]{4}\b"
)
_RE_PGP_FPR_CONTIG = re.compile(r"\b[0-9A-Fa-f]{40}\b")

# .onion v2 (16) or v3 (56) base32 host, optional scheme and path.
_RE_ONION = re.compile(
    r"\b(?:(https?)://)?([a-z2-7]{16}|[a-z2-7]{56})\.onion\b([^\s\"'<>)\]]*)",
    re.IGNORECASE,
)

_RE_BTC = re.compile(
    r"\b(bc1[a-z0-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"
)
_RE_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
# Monero: standard (95) prefix 4/8, or integrated (106).
_RE_XMR = re.compile(
    r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?:[1-9A-HJ-NP-Za-km-z]{11})?\b"
)

_RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}\b"
)
_RE_XMPP_URI = re.compile(
    r"\b(?:xmpp|jabber)\s*:\s*([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63})",
    re.IGNORECASE,
)

# Heuristic username signals.
_RE_AT_HANDLE = re.compile(r"(?<![\w@./])@([A-Za-z0-9_]{3,32})\b")
_RE_LABELLED_HANDLE = re.compile(
    r"\b(?:vendor|seller|user(?:name)?|handle|author|nick(?:name)?|aka|posted\s+by|"
    r"sold\s+by)\s*[:\-]?\s*@?([A-Za-z0-9_.\-]{3,32})\b",
    re.IGNORECASE,
)


class IdentifierExtractor:
    """Extracts identifiers from a block of text.

    The extractor removes onion hosts and PGP blocks from a working copy of the
    text before running the crypto/contact patterns, so those long base32/base64
    regions cannot masquerade as wallet addresses or emails.
    """

    CONTEXT_RADIUS = 40

    def extract(self, text: str) -> list[Identifier]:
        if not text:
            return []
        found: list[Identifier] = []

        # 1) PGP blocks first, then blank them out of the working text.
        #
        # The armored block is parsed, not merely hashed. A content hash cannot be
        # matched across sites (armor, comments and wrapping all differ), whereas
        # the key fingerprint is byte-identical wherever the same actor publishes
        # the same key — and the User ID packet inside frequently carries the
        # owner's chosen name and email, which is the single most identifying
        # artifact a vendor page tends to leak.
        working = text
        for m in _RE_PGP_BLOCK.finditer(text):
            block = m.group(0)
            normalized = re.sub(r"\s+", "", block).encode("utf-8", "replace")
            digest = hashlib.sha256(normalized).hexdigest()
            found.append(
                Identifier(PGP_BLOCK, f"sha256:{digest}", context=block)
            )
            found.extend(self._pgp_key_identifiers(block))
        working = _RE_PGP_BLOCK.sub(" ", working)

        # 2) Onion links, then blank the hosts so they can't feed other patterns.
        found.extend(self._onions(working))
        working = _RE_ONION.sub(" ", working)

        # 3) PGP fingerprints (grouped is high-confidence; contiguous is flagged).
        found.extend(self._fingerprints(working))

        # 4) Crypto, contacts, usernames on the cleaned working text.
        found.extend(self._crypto(working))
        found.extend(self._contacts(working))
        found.extend(self._usernames(working))

        return self.dedup(found)

    # ---- per-type helpers -------------------------------------------------

    def _ctx(self, text: str, start: int, end: int) -> str:
        a = max(0, start - self.CONTEXT_RADIUS)
        b = min(len(text), end + self.CONTEXT_RADIUS)
        return re.sub(r"\s+", " ", text[a:b]).strip()

    def _onions(self, text: str) -> list[Identifier]:
        out: list[Identifier] = []
        for m in _RE_ONION.finditer(text):
            scheme = (m.group(1) or "http").lower()
            host = m.group(2).lower()
            path = m.group(3) or ""
            # Trim trailing punctuation that commonly abuts a URL in prose.
            path = path.rstrip(".,;:!?")
            value = f"{scheme}://{host}.onion{path}"
            out.append(Identifier(ONION_URL, value, self._ctx(text, m.start(), m.end())))
        return out

    @staticmethod
    def _pgp_key_identifiers(block: str) -> list[Identifier]:
        """Parse an armored key into fingerprint / UID identifiers.

        A block that will not parse is not an error worth failing a page over —
        the content hash emitted by the caller still records that a key was seen.
        """
        from .pgp import PgpParseError, parse_key  # local: keeps this module standalone

        try:
            key = parse_key(block)
        except (PgpParseError, ValueError, IndexError):
            return []

        crc = "" if key.checksum_ok else " (ARMOR CHECKSUM FAILED)"
        out = [
            Identifier(
                PGP_FINGERPRINT,
                key.fingerprint,
                context=f"parsed from armored key: v{key.version} {key.algorithm}, "
                        f"key ID {key.key_id}{crc}",
            )
        ]
        for uid in key.uids:
            if uid.email:
                out.append(Identifier(
                    EMAIL, uid.email,
                    context=f"PGP User ID of key {key.key_id}: {uid.raw!r}",
                ))
            if uid.name:
                out.append(Identifier(
                    PGP_UID_NAME, uid.name,
                    context=f"PGP User ID of key {key.key_id}: {uid.raw!r}",
                ))
        for sub in key.subkey_fingerprints:
            out.append(Identifier(
                PGP_FINGERPRINT, sub,
                context=f"subkey of {key.key_id}", heuristic=True,
            ))
        return out

    def _fingerprints(self, text: str) -> list[Identifier]:
        out: list[Identifier] = []
        seen: set[str] = set()
        for m in _RE_PGP_FPR_GROUPED.finditer(text):
            norm = re.sub(r"\s+", "", m.group(0)).upper()
            seen.add(norm)
            out.append(
                Identifier(PGP_FINGERPRINT, norm, self._ctx(text, m.start(), m.end()))
            )
        for m in _RE_PGP_FPR_CONTIG.finditer(text):
            norm = m.group(0).upper()
            if norm in seen:
                continue
            # Contiguous 40-hex could also be a git SHA etc.; flag as heuristic.
            out.append(
                Identifier(
                    PGP_FINGERPRINT,
                    norm,
                    self._ctx(text, m.start(), m.end()),
                    heuristic=True,
                )
            )
        return out

    def _crypto(self, text: str) -> list[Identifier]:
        out: list[Identifier] = []
        for m in _RE_BTC.finditer(text):
            addr = m.group(1)
            if addr.lower().startswith("bc1"):
                if not bech32_valid(addr, expected_hrp="bc"):
                    continue
            elif not base58check_valid(addr):
                continue
            out.append(Identifier(BTC_ADDRESS, addr, self._ctx(text, m.start(), m.end())))
        for m in _RE_ETH.finditer(text):
            # Shape-valid only (no keccak/EIP-55 check without a dependency).
            out.append(
                Identifier(
                    ETH_ADDRESS, m.group(0), self._ctx(text, m.start(), m.end()),
                    heuristic=True,
                )
            )
        for m in _RE_XMR.finditer(text):
            out.append(
                Identifier(
                    XMR_ADDRESS, m.group(0), self._ctx(text, m.start(), m.end()),
                    heuristic=True,
                )
            )
        return out

    def _contacts(self, text: str) -> list[Identifier]:
        out: list[Identifier] = []
        xmpp_values: set[str] = set()

        # Explicit xmpp:/jabber: URIs are unambiguous XMPP JIDs.
        for m in _RE_XMPP_URI.finditer(text):
            jid = m.group(1)
            xmpp_values.add(jid.lower())
            out.append(Identifier(XMPP, jid, self._ctx(text, m.start(), m.end())))

        for m in _RE_EMAIL.finditer(text):
            addr = m.group(0)
            if addr.lower() in xmpp_values:
                continue  # already captured as XMPP
            window = text[max(0, m.start() - 25): m.end() + 25].lower()
            is_xmpp = "jabber" in window or "xmpp" in window or addr.endswith(".onion")
            out.append(
                Identifier(
                    XMPP if is_xmpp else EMAIL,
                    addr,
                    self._ctx(text, m.start(), m.end()),
                    heuristic=is_xmpp,  # keyword-inferred XMPP is a guess
                )
            )
        return out

    def _usernames(self, text: str) -> list[Identifier]:
        out: list[Identifier] = []
        for regex in (_RE_AT_HANDLE, _RE_LABELLED_HANDLE):
            for m in regex.finditer(text):
                handle = m.group(1)
                out.append(
                    Identifier(
                        USERNAME,
                        handle,
                        self._ctx(text, m.start(), m.end()),
                        heuristic=True,  # always analyst-review, never ground truth
                    )
                )
        return out

    @staticmethod
    def dedup(items: list[Identifier]) -> list[Identifier]:
        """Deduplicate on (type, value), keeping the first (context-bearing) hit."""
        seen: set[tuple[str, str]] = set()
        out: list[Identifier] = []
        for it in items:
            key = (it.type, it.value)
            if key in seen:
                continue
            seen.add(key)
            out.append(it)
        return out


    #: Retained so existing callers of the former private name keep working.
    _dedup = dedup


def onion_hosts(text: str) -> set[str]:
    """Convenience: all distinct ``<host>.onion`` hostnames present in text."""
    return {f"{m.group(2).lower()}.onion" for m in _RE_ONION.finditer(text or "")}
