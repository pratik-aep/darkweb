"""Tor-routed HTTP session.

Wraps ``requests`` so that:
  * every request goes through the local Tor SOCKS5 proxy using the ``socks5h``
    scheme (so DNS, including ``.onion`` resolution, happens inside Tor);
  * transient failures are retried with capped exponential backoff + jitter,
    because onion services are frequently slow or briefly unreachable;
  * requests to the same host are spaced out by a polite minimum delay;
  * a fresh Tor circuit (NEWNYM) is requested every N requests via the control
    port using ``stem``.

Third-party deps (``PySocks`` for the socks transport, ``stem`` for the control
port) are imported lazily so that the rest of the package — extraction, storage,
querying, tests — works even where they are not installed. Only the code paths
that actually need Tor will raise if a dependency is missing.
"""
from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import requests
import urllib3

from .config import Config

# Errors that a flaky onion service can raise mid-read (a truncated/broken
# response) which are NOT requests.RequestException, so they would otherwise
# escape the retry loop and crash a long-running crawl or --watch loop.
_FETCH_ERRORS = (requests.RequestException, urllib3.exceptions.HTTPError, OSError)

logger = logging.getLogger("darkosint.tor")


@dataclass
class FetchResult:
    """Outcome of a single fetch (after retries).

    ``headers`` holds the full response header set. It is kept because
    ``Server``, ``X-Powered-By``, ``ETag`` and ``Set-Cookie`` are the "default
    service banner" evidence class — they identify the software stack behind a
    hidden service and are only observable at fetch time.
    """

    url: str
    ok: bool
    status: int | None = None
    text: str = ""
    content: bytes = b""
    content_type: str = ""
    final_url: str = ""
    error: str = ""
    headers: dict[str, str] = field(default_factory=dict)


class TorUnavailableError(RuntimeError):
    """Raised when the SOCKS proxy transport cannot be used at all."""


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


class TorSession:
    """A politeness-aware, retrying HTTP client pinned to Tor."""

    def __init__(self, config: Config):
        self.cfg = config
        self._session = self._build_session()
        self._request_count = 0
        self._last_request_at: dict[str, float] = {}

    # ---- setup ------------------------------------------------------------

    def _build_session(self) -> requests.Session:
        # Fail early and clearly if PySocks is absent: requests needs it to speak
        # SOCKS, otherwise socks5h:// silently would not work.
        try:
            import socks  # noqa: F401  (PySocks) -- import for presence check
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise TorUnavailableError(
                "PySocks is required for Tor routing. Install it with "
                "`pip install PySocks` (see requirements.txt)."
            ) from exc

        session = requests.Session()
        proxy = self.cfg.tor.proxy_url
        session.proxies = {"http": proxy, "https": proxy}
        session.headers.update(
            {
                "User-Agent": self.cfg.http.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Connection": "keep-alive",
            }
        )
        logger.debug("HTTP session bound to Tor proxy %s", proxy)
        return session

    # ---- politeness -------------------------------------------------------

    def _respect_delay(self, host: str) -> None:
        """Sleep so consecutive hits on the same host honour per_host_delay."""
        delay = self.cfg.http.per_host_delay
        last = self._last_request_at.get(host)
        if last is not None:
            elapsed = time.monotonic() - last
            wait = delay - elapsed
            if wait > 0:
                logger.debug("Politeness: sleeping %.1fs before %s", wait, host)
                time.sleep(wait)
        self._last_request_at[host] = time.monotonic()

    # ---- circuit rotation -------------------------------------------------

    def maybe_rotate(self) -> None:
        """Request a new Tor identity every rotate_every requests."""
        every = self.cfg.tor.rotate_every
        if every and every > 0 and self._request_count and (
            self._request_count % every == 0
        ):
            self.rotate_identity()

    def rotate_identity(self) -> bool:
        """Signal NEWNYM over the control port. Returns True on success.

        Failure here is non-fatal: we log and continue on the existing circuit.
        """
        try:
            from stem import Signal
            from stem.control import Controller
        except ImportError:  # pragma: no cover - environment dependent
            logger.warning(
                "stem not installed; cannot rotate Tor circuit. "
                "Install it with `pip install stem` to enable NEWNYM rotation."
            )
            return False

        try:
            with Controller.from_port(port=self.cfg.tor.control_port) as controller:
                if self.cfg.tor.control_password:
                    controller.authenticate(password=self.cfg.tor.control_password)
                else:
                    controller.authenticate()  # cookie auth or open control port
                if not controller.is_newnym_available():
                    wait = controller.get_newnym_wait()
                    logger.debug("NEWNYM rate-limited; waiting %.1fs", wait)
                    time.sleep(wait)
                controller.signal(Signal.NEWNYM)
                # Give Tor a moment to actually build the new circuit.
                time.sleep(controller.get_newnym_wait())
                logger.info("Rotated Tor circuit (new identity requested)")
                return True
        except Exception as exc:  # noqa: BLE001 - want to survive any control error
            logger.warning("Circuit rotation failed (continuing): %s", exc)
            return False

    # ---- fetching ---------------------------------------------------------

    def get(self, url: str) -> FetchResult:
        """GET a URL through Tor with politeness, retries, and backoff.

        Only ever issues GET requests — this collector is passive by design.
        """
        host = _host_of(url)
        self._respect_delay(host)

        attempts = self.cfg.http.max_retries + 1
        last_error = ""
        for attempt in range(attempts):
            try:
                logger.info("GET %s (attempt %d/%d)", url, attempt + 1, attempts)
                resp = self._session.get(
                    url,
                    timeout=self.cfg.http.timeout,
                    stream=True,
                    allow_redirects=True,
                )
                content = resp.raw.read(
                    self.cfg.http.max_bytes + 1, decode_content=True
                )
                truncated = len(content) > self.cfg.http.max_bytes
                if truncated:
                    content = content[: self.cfg.http.max_bytes]
                    logger.warning(
                        "Response from %s exceeded max_bytes; truncated to %d bytes",
                        url,
                        self.cfg.http.max_bytes,
                    )
                resp.close()

                # resp.apparent_encoding is unreliable here because we drained
                # resp.raw ourselves, so use the header charset with a UTF-8
                # fallback (most onion pages are UTF-8).
                encoding = resp.encoding or "utf-8"
                try:
                    text = content.decode(encoding, errors="replace")
                except (LookupError, TypeError):
                    text = content.decode("utf-8", errors="replace")

                self._register_success()
                logger.info("  -> %s %s (%d bytes)", resp.status_code, url, len(content))
                return FetchResult(
                    url=url,
                    ok=resp.ok,
                    status=resp.status_code,
                    text=text,
                    content=content,
                    content_type=resp.headers.get("Content-Type", ""),
                    final_url=str(resp.url),
                    headers={k: v for k, v in resp.headers.items()},
                )
            except _FETCH_ERRORS as exc:
                # Includes urllib3 ProtocolError/IncompleteRead raised while
                # draining a truncated response — retry rather than crash.
                last_error = f"{type(exc).__name__}: {exc}"
                logger.warning("  fetch error for %s: %s", url, last_error)
                if attempt < attempts - 1:
                    self._sleep_backoff(attempt)

        logger.error("Giving up on %s after %d attempts", url, attempts)
        return FetchResult(url=url, ok=False, error=last_error)

    def _register_success(self) -> None:
        self._request_count += 1
        self.maybe_rotate()

    def _sleep_backoff(self, attempt: int) -> None:
        base = self.cfg.http.backoff_base ** (attempt + 1)
        wait = min(self.cfg.http.backoff_cap, base)
        wait += random.uniform(0, wait * 0.25)  # jitter to avoid lockstep retries
        logger.debug("Backing off %.1fs before retry", wait)
        time.sleep(wait)

    # ---- diagnostics ------------------------------------------------------

    def check_connectivity(self) -> FetchResult:
        """Confirm traffic is actually exiting through Tor.

        Uses the Tor Project's check endpoint; a healthy result contains
        "Congratulations. This browser is configured to use Tor."
        """
        return self.get("https://check.torproject.org/")

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "TorSession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
