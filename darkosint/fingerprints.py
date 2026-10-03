"""Infrastructure fingerprints and clearnet artifacts.

These are the passive signals that let an onion service be matched against
clearnet infrastructure. Nothing here issues a request: every function takes
bytes or headers that were *already served* to the collector and turns them into
correlation keys.

Signal classes
--------------
``favicon_mmh3``
    MurmurHash3 (x86, 32-bit) over the base64-encoded favicon, which is the
    hashing convention Shodan and Censys index under ``http.favicon.hash``. An
    operator who serves the same favicon from their onion service and their
    clearnet origin is directly searchable by this integer.
``server_banner`` / ``powered_by`` / ``cookie_name``
    Default service banners — the problem space's classic misconfiguration. A
    distinctive ``Server:`` string narrows the clearnet candidate set sharply.
``analytics_id``
    Google Analytics / GTM / AdSense IDs are per-*operator*, not per-site, so the
    same ID on an onion service and a clearnet domain is strong attribution.
``clearnet_domain`` / ``ipv4``
    Absolute clearnet URLs and hardcoded IPs left in onion page markup.
``etag``
    Inode-derived ETags leak filesystem details that can match a clearnet host.

All values are emitted as :class:`~darkosint.extractors.Identifier` rows, so the
existing cross-source pivot machinery indexes them for free.
"""
from __future__ import annotations

import base64
import re
from urllib.parse import urlsplit

from .extractors import Identifier

# ---- identifier type constants -------------------------------------------

SERVER_BANNER = "server_banner"
POWERED_BY = "powered_by"
COOKIE_NAME = "cookie_name"
ETAG = "etag"
FAVICON_HASH = "favicon_mmh3"
ANALYTICS_ID = "analytics_id"
CLEARNET_DOMAIN = "clearnet_domain"
IPV4 = "ipv4"
S3_BUCKET = "s3_bucket"
GENERATOR = "generator"

TLS_CN = "tls_cn"
TLS_SAN = "tls_san"
TLS_FINGERPRINT = "tls_fingerprint"
TLS_SPKI = "tls_spki"
TLS_ISSUER = "tls_issuer"
TLS_SERIAL = "tls_serial"

#: Identifier types produced by this module (used by the correlation engine).
INFRA_TYPES = (
    SERVER_BANNER, POWERED_BY, COOKIE_NAME, ETAG, FAVICON_HASH, ANALYTICS_ID,
    CLEARNET_DOMAIN, IPV4, S3_BUCKET, GENERATOR,
    TLS_CN, TLS_SAN, TLS_FINGERPRINT, TLS_SPKI, TLS_ISSUER, TLS_SERIAL,
)


# ---------------------------------------------------------------------------
# MurmurHash3 x86 32-bit
# ---------------------------------------------------------------------------

_M32 = 0xFFFFFFFF


def _rotl32(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & _M32


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32. Returns the value as a *signed* 32-bit int.

    Signed output matches the ``mmh3.hash`` convention that Shodan's
    ``http.favicon.hash`` search operator expects, so the value can be pasted
    straight into a Shodan/Censys query.
    """
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & _M32

    nblocks = length // 4
    for i in range(nblocks):
        k1 = int.from_bytes(data[i * 4:i * 4 + 4], "little")
        k1 = (k1 * c1) & _M32
        k1 = _rotl32(k1, 15)
        k1 = (k1 * c2) & _M32
        h1 ^= k1
        h1 = _rotl32(h1, 13)
        h1 = (h1 * 5 + 0xE6546B64) & _M32

    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & _M32
        k1 = _rotl32(k1, 15)
        k1 = (k1 * c2) & _M32
        h1 ^= k1

    h1 ^= length
    # fmix32
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & _M32
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & _M32
    h1 ^= h1 >> 16

    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(raw: bytes) -> int:
    """Shodan-compatible favicon hash: mmh3 over the base64 of the icon bytes.

    The base64 must be the line-wrapped form (76 columns, trailing newline) that
    ``codecs.encode(data, 'base64')`` produces, because that is what Shodan
    hashed when it built its index.
    """
    return murmur3_32(base64.encodebytes(raw))


# ---------------------------------------------------------------------------
# response headers -> banners
# ---------------------------------------------------------------------------

#: Headers whose values are operator-controlled banners worth recording.
_BANNER_HEADERS = {
    "server": SERVER_BANNER,
    "x-powered-by": POWERED_BY,
    "x-aspnet-version": POWERED_BY,
    "x-aspnetmvc-version": POWERED_BY,
    "x-generator": GENERATOR,
    "x-drupal-cache": GENERATOR,
    "x-varnish": GENERATOR,
}

# A banner is only a useful *pivot* if it is more specific than the stock string
# a distro ships. Generic ones are still recorded, but flagged heuristic.
_GENERIC_BANNERS = re.compile(
    r"^(nginx|apache|cloudflare|openresty|caddy|lighttpd|gunicorn|werkzeug)\s*$",
    re.IGNORECASE,
)


def header_identifiers(headers: dict[str, str], url: str = "") -> list[Identifier]:
    """Turn response headers into banner / cookie / ETag identifiers."""
    out: list[Identifier] = []
    lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}

    for header, type_ in _BANNER_HEADERS.items():
        value = lowered.get(header, "").strip()
        if not value:
            continue
        generic = bool(_GENERIC_BANNERS.match(value))
        out.append(
            Identifier(
                type_,
                value,
                context=f"{header}: {value} (from {url})" if url else f"{header}: {value}",
                # A bare "nginx" matches half the internet; keep it, flag it.
                heuristic=generic,
            )
        )

    etag = lowered.get("etag", "").strip().strip('"W/')
    if etag:
        out.append(
            Identifier(
                ETAG, etag, context=f"ETag on {url}",
                # Only inode-style ETags ("hex-hex-hex") are host-identifying.
                heuristic=not re.match(r"^[0-9a-f]+-[0-9a-f]+(-[0-9a-f]+)?$", etag, re.I),
            )
        )

    # Cookie *names* (never values — values are session secrets we do not keep).
    cookie = lowered.get("set-cookie", "")
    for name in re.findall(r"(?:^|,\s*)([A-Za-z0-9_\-]{2,64})=", cookie):
        out.append(
            Identifier(
                COOKIE_NAME, name, context=f"Set-Cookie name on {url}", heuristic=True
            )
        )
    return out


# ---------------------------------------------------------------------------
# certificate -> identifiers
# ---------------------------------------------------------------------------


def certificate_identifiers(cert, url: str = "") -> list[Identifier]:
    """Turn a parsed :class:`~darkosint.x509.Certificate` into identifiers.

    A non-``.onion`` DNS name in the certificate is the strongest passive
    attribution signal in the whole toolkit, so it is emitted both as a TLS
    identifier and as a ``clearnet_domain``.
    """
    out: list[Identifier] = []
    where = f" (observed on {url})" if url else ""

    if cert.sha256:
        out.append(Identifier(TLS_FINGERPRINT, cert.sha256, f"cert SHA-256{where}"))
    if cert.spki_sha256:
        out.append(
            Identifier(
                TLS_SPKI, cert.spki_sha256,
                f"public-key SHA-256 — survives cert reissue{where}",
            )
        )
    if cert.serial:
        out.append(Identifier(TLS_SERIAL, cert.serial, f"cert serial{where}", heuristic=True))
    if cert.subject_cn:
        out.append(Identifier(TLS_CN, cert.subject_cn, f"cert subject CN{where}"))
    if cert.issuer_cn:
        out.append(
            Identifier(TLS_ISSUER, cert.issuer_cn, f"cert issuer CN{where}", heuristic=True)
        )
    for name in cert.san_dns:
        out.append(Identifier(TLS_SAN, name.lower(), f"cert SAN{where}"))
    for ip in cert.san_ip:
        out.append(Identifier(IPV4, ip, f"cert SAN iPAddress{where}"))
    for addr in cert.san_email:
        out.append(Identifier("email", addr.lower(), f"cert SAN rfc822Name{where}"))

    for name in cert.clearnet_names():
        out.append(
            Identifier(
                CLEARNET_DOMAIN, name,
                context=f"CLEARNET NAME IN TLS CERTIFICATE{where} — "
                        f"certificate asserts a non-onion domain",
            )
        )
    return out


# ---------------------------------------------------------------------------
# page body -> clearnet artifacts
# ---------------------------------------------------------------------------

_RE_ANALYTICS = re.compile(
    r"\b(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{8,12}|GTM-[A-Z0-9]{4,10}|"
    r"ca-pub-\d{10,20})\b"
)
_RE_FB_PIXEL = re.compile(r"fbq\s*\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]")
_RE_S3 = re.compile(
    r"\b([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-]"
    r"(?:[a-z0-9\-]+\.)?amazonaws\.com\b", re.IGNORECASE
)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_RE_ABS_URL = re.compile(r"\bhttps?://([A-Za-z0-9.\-]+\.[A-Za-z]{2,24})(?::\d+)?\b")
_RE_GENERATOR_META = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']{2,120})[\"']",
    re.IGNORECASE,
)

# Private/reserved ranges are host-local noise, not attribution.
_RE_PRIVATE_IP = re.compile(
    r"^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|"
    r"22[4-9]\.|23\d\.|24\d\.|25[0-5]\.)"
)

# CDNs and common third parties are on every site; they attribute nothing.
_COMMON_DOMAINS = {
    "www.w3.org", "schema.org", "fonts.googleapis.com", "fonts.gstatic.com",
    "ajax.googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net",
    "unpkg.com", "code.jquery.com", "www.google.com", "google.com",
    "gmpg.org", "purl.org", "creativecommons.org", "www.gnu.org",
    "github.com", "www.mozilla.org", "developer.mozilla.org",
    "torproject.org", "www.torproject.org", "bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com",
}


def _is_noise_domain(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    if d in _COMMON_DOMAINS or d.endswith(".onion"):
        return True
    return d.startswith("www.w3.org") or d.endswith(".local")


def page_artifacts(html: str, url: str = "") -> list[Identifier]:
    """Extract clearnet-correlation artifacts from already-fetched page markup.

    Runs on raw HTML (not visible text) on purpose: analytics snippets, absolute
    asset URLs, and generator meta tags live in markup and attributes, which is
    exactly where an operator's clearnet infrastructure leaks.
    """
    out: list[Identifier] = []
    if not html:
        return out
    where = f" on {url}" if url else ""
    self_host = (urlsplit(url).hostname or "").lower()

    for m in _RE_ANALYTICS.finditer(html):
        out.append(
            Identifier(
                ANALYTICS_ID, m.group(1),
                context=f"analytics/tag ID{where} — operator-scoped, not site-scoped",
            )
        )
    for m in _RE_FB_PIXEL.finditer(html):
        out.append(
            Identifier(ANALYTICS_ID, f"fb:{m.group(1)}", context=f"Facebook pixel{where}")
        )
    for m in _RE_S3.finditer(html):
        out.append(
            Identifier(S3_BUCKET, m.group(1).lower(), context=f"S3 bucket reference{where}")
        )
    for m in _RE_GENERATOR_META.finditer(html):
        out.append(
            Identifier(
                GENERATOR, m.group(1).strip(),
                context=f"<meta name=generator>{where}", heuristic=True,
            )
        )
    for m in _RE_IPV4.finditer(html):
        ip = m.group(0)
        if _RE_PRIVATE_IP.match(ip):
            continue
        out.append(
            Identifier(IPV4, ip, context=f"hardcoded IPv4{where}", heuristic=True)
        )

    seen_domains: set[str] = set()
    for m in _RE_ABS_URL.finditer(html):
        domain = m.group(1).lower().rstrip(".")
        if domain == self_host or domain in seen_domains or _is_noise_domain(domain):
            continue
        seen_domains.add(domain)
        out.append(
            Identifier(
                CLEARNET_DOMAIN, domain,
                context=f"absolute clearnet URL{where}",
                # A referenced domain is weaker evidence than one in a TLS cert.
                heuristic=True,
            )
        )
    return out


def favicon_identifier(raw: bytes, url: str = "") -> Identifier | None:
    """Build the favicon-hash identifier for already-downloaded icon bytes."""
    if not raw:
        return None
    value = favicon_hash(raw)
    return Identifier(
        FAVICON_HASH,
        str(value),
        context=(
            f"favicon mmh3{' from ' + url if url else ''} — "
            f'pivot with Shodan `http.favicon.hash:{value}`'
        ),
    )
