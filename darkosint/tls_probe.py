"""TLS certificate capture through Tor.

``requests`` cannot hand back a peer certificate for a host it did not verify,
and onion services are self-signed by definition, so certificate capture needs
its own socket: a SOCKS5 tunnel to the Tor daemon, a TLS handshake with
verification disabled, and the raw DER read straight off the socket.

``rdns=True`` is essential — it makes PySocks send the *hostname* to Tor rather
than resolving it locally, which is both what makes ``.onion`` addresses work at
all and what stops a DNS lookup leaking to the local resolver.

Scope note
----------
A TLS handshake is a connection the operator did not serve us unprompted, so it
is treated as opt-in and bounded:

* for a URL already fetched over ``https://`` the handshake is happening anyway,
  so capturing the certificate adds no new contact — this is on by default;
* reaching for port 443 on a host only ever fetched over ``http://`` is a
  *separate* connection, so it is gated behind its own config flag and is off by
  default.

In both cases this only completes a handshake and reads what the server presents.
It sends no application data, requests no resource, and never attempts to
negotiate anything the server does not offer.
"""
from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .config import Config
from .x509 import Certificate, parse_der

logger = logging.getLogger("darkosint.tls")

DEFAULT_TLS_PORT = 443


@dataclass
class TlsObservation:
    """What one handshake revealed."""

    host: str
    port: int
    ok: bool = False
    certificate: Certificate | None = None
    chain: list[Certificate] = field(default_factory=list)
    tls_version: str = ""
    cipher: str = ""
    alpn: str = ""
    error: str = ""


def _socks_socket(cfg: Config, host: str, port: int, timeout: float):
    """Open a SOCKS5 socket to ``host:port`` through the Tor daemon."""
    try:
        import socks  # PySocks
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "PySocks is required for TLS capture over Tor (pip install PySocks)"
        ) from exc

    sock = socks.socksocket()
    sock.set_proxy(
        socks.SOCKS5,
        cfg.tor.socks_host,
        cfg.tor.socks_port,
        rdns=True,  # resolve through Tor; required for .onion, prevents DNS leak
    )
    sock.settimeout(timeout)
    sock.connect((host, port))
    return sock


def _permissive_context() -> ssl.SSLContext:
    """A context that completes a handshake with any peer, verifying nothing.

    Verification is disabled deliberately: onion service certificates are
    self-signed, and the goal is to *read* the certificate, never to trust it.
    Nothing is transmitted over the resulting socket.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Accept legacy servers too: an outdated TLS stack is itself a fingerprint.
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (AttributeError, ValueError):  # pragma: no cover - platform dependent
        pass
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:  # pragma: no cover - platform dependent
        pass
    return ctx


def probe(
    cfg: Config,
    host: str,
    port: int = DEFAULT_TLS_PORT,
    server_hostname: str | None = None,
) -> TlsObservation:
    """Complete a TLS handshake through Tor and capture the presented chain."""
    obs = TlsObservation(host=host, port=port)
    timeout = min(cfg.http.timeout, 45.0)
    sni = server_hostname or host

    try:
        raw_sock = _socks_socket(cfg, host, port, timeout)
    except Exception as exc:  # noqa: BLE001 - any transport failure is non-fatal
        obs.error = f"{type(exc).__name__}: {exc}"
        logger.debug("TLS connect failed for %s:%d — %s", host, port, obs.error)
        return obs

    try:
        ctx = _permissive_context()
        with ctx.wrap_socket(raw_sock, server_hostname=sni) as tls:
            der = tls.getpeercert(binary_form=True)
            obs.tls_version = tls.version() or ""
            cipher = tls.cipher()
            obs.cipher = cipher[0] if cipher else ""
            obs.alpn = tls.selected_alpn_protocol() or ""

            if der:
                obs.certificate = parse_der(der)
                obs.ok = True

            # Python 3.10+ can hand back the rest of the presented chain; an
            # intermediate's Organization field is occasionally the giveaway.
            getter = getattr(tls, "get_unverified_chain", None)
            if getter is not None:
                try:
                    for entry in getter() or ():
                        obs.chain.append(parse_der(entry.public_bytes(ssl.ENCODING_DER)))
                except Exception:  # noqa: BLE001 - chain is a bonus, never required
                    pass
    except (ssl.SSLError, OSError, ValueError) as exc:
        obs.error = f"{type(exc).__name__}: {exc}"
        logger.debug("TLS handshake failed for %s:%d — %s", host, port, obs.error)
    finally:
        try:
            raw_sock.close()
        except OSError:
            pass

    if obs.ok and obs.certificate is not None:
        clearnet = obs.certificate.clearnet_names()
        if clearnet:
            logger.warning(
                "CLEARNET NAME IN CERTIFICATE for %s: %s (passive observation)",
                host,
                ", ".join(clearnet),
            )
        else:
            logger.info(
                "TLS certificate captured for %s (CN=%r, %s)",
                host, obs.certificate.subject_cn, obs.tls_version,
            )
    return obs


def probe_url(cfg: Config, url: str, force: bool = False) -> TlsObservation | None:
    """Probe the TLS endpoint implied by ``url``.

    Returns ``None`` when the URL is plain HTTP and ``force`` was not set, which
    is the default posture: no extra connection the page fetch did not already
    make.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host:
        return None
    if parts.scheme != "https" and not force:
        return None
    port = parts.port or (443 if parts.scheme == "https" else DEFAULT_TLS_PORT)
    return probe(cfg, host, port, server_hostname=host)


def direct_probe(host: str, port: int = DEFAULT_TLS_PORT, timeout: float = 20.0) -> TlsObservation:
    """Probe a **clearnet** host directly (no Tor), for the comparison side.

    Correlation needs both halves: the certificate an onion service presents and
    the certificate a candidate clearnet host presents. This is the clearnet
    half, and it deliberately does not go through Tor — the candidate host is a
    public server being checked against public data.
    """
    obs = TlsObservation(host=host, port=port)
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        obs.error = f"{type(exc).__name__}: {exc}"
        return obs
    try:
        ctx = _permissive_context()
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            obs.tls_version = tls.version() or ""
            cipher = tls.cipher()
            obs.cipher = cipher[0] if cipher else ""
            if der:
                obs.certificate = parse_der(der)
                obs.ok = True
    except (ssl.SSLError, OSError, ValueError) as exc:
        obs.error = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            raw.close()
        except OSError:
            pass
    return obs
