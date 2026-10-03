"""Crawl orchestration.

Ties the pieces together for one collection run:

  seed URLs -> frontier (BFS, depth/page bounded, visited-tracked)
            -> fetch via Tor (politeness, retries, rotation)
            -> save raw HTML snapshot to disk + metadata (evidentiary record)
            -> select per-site parser -> extract identifiers + onion links
            -> persist source, snapshot, identifiers, links to SQLite
            -> enqueue newly discovered onion links (if expansion enabled)

Safety posture is passive and detection-only. The crawler issues GET requests,
saves what it is served, and — if a page merely looks like an exposed endpoint
(e.g. Apache /server-status output or an admin panel) — it NOTES that as an
``exposure_note`` identifier and logs it. It never probes for such endpoints and
never acts on them.
"""
from __future__ import annotations

import hashlib
import logging
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

from .config import Config
from .extractors import Identifier, IdentifierExtractor, ONION_URL
from .fingerprints import (
    certificate_identifiers,
    favicon_identifier,
    header_identifiers,
    page_artifacts,
)
from .parsers import get_parser_for
from .pgp import parse_all as parse_pgp_keys
from .secrets import redact_secrets
from .storage import Storage
from .tor_session import TorSession

logger = logging.getLogger("darkosint.crawler")

EXPOSURE_NOTE = "exposure_note"

# Passive signals that a fetched page is an exposed endpoint. Detection only:
# these match content we were already served, they never drive a request.
_EXPOSURE_SIGNALS: list[tuple[str, re.Pattern[str]]] = [
    ("apache_server_status", re.compile(r"Apache Server Status for", re.I)),
    ("apache_server_info", re.compile(r"Apache Server Information", re.I)),
    ("mod_status_table", re.compile(r"<title>[^<]*Server Status[^<]*</title>", re.I)),
    ("directory_listing", re.compile(r"<title>\s*Index of /", re.I)),
    ("phpinfo", re.compile(r"phpinfo\(\)", re.I)),
    ("admin_panel", re.compile(r"<title>[^<]*(admin(istration)?\s+panel|dashboard)[^<]*</title>", re.I)),
]


@dataclass
class CrawlStats:
    pages_fetched: int = 0
    pages_failed: int = 0
    identifiers_added: int = 0
    links_discovered: int = 0
    exposures_noted: int = 0
    certificates_captured: int = 0
    clearnet_names_found: int = 0
    pgp_keys_parsed: int = 0
    documents_stored: int = 0
    identifiers_by_type: dict[str, int] = field(default_factory=dict)

    def bump_type(self, type_: str, n: int = 1) -> None:
        self.identifiers_by_type[type_] = self.identifiers_by_type.get(type_, 0) + n


@dataclass(order=True)
class _FrontierItem:
    depth: int
    url: str = field(compare=False)
    parent: str | None = field(default=None, compare=False)


def _normalize_url(url: str) -> str:
    """Canonicalize for visited-tracking: lowercase host, strip fragment."""
    parts = urlsplit(url)
    scheme = parts.scheme or "http"
    host = (parts.hostname or "").lower()
    port = f":{parts.port}" if parts.port else ""
    path = parts.path or "/"
    return urlunsplit((scheme, host + port, path, parts.query, ""))


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


class Crawler:
    def __init__(
        self,
        config: Config,
        session: TorSession,
        storage: Storage,
        output_dir: str | Path,
        extractor: IdentifierExtractor | None = None,
    ):
        self.cfg = config
        self.session = session
        self.storage = storage
        self.extractor = extractor or IdentifierExtractor()
        self.snapshot_dir = Path(output_dir) / "snapshots"
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        self.visited: set[str] = set()
        # TLS and favicon are per-host properties, so capture them once per host
        # rather than once per page.
        self._tls_seen: set[str] = set()
        self._favicon_seen: set[str] = set()
        self._pending_cert = None

    # ---- snapshotting -----------------------------------------------------

    def _save_snapshot(self, url: str, content: bytes) -> tuple[Path, str]:
        """Write raw bytes to disk under a content-addressed name; return path+sha."""
        sha = hashlib.sha256(content).hexdigest()
        host = _host_of(url) or "unknown"
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        host_dir = self.snapshot_dir / host
        host_dir.mkdir(parents=True, exist_ok=True)
        path = host_dir / f"{ts}_{sha[:16]}.html"
        path.write_bytes(content)
        logger.debug("Saved snapshot %s (%d bytes)", path, len(content))
        return path, sha

    # ---- exposure detection (passive, note-only) --------------------------

    def _note_exposures(self, url: str, html: str) -> list[Identifier]:
        notes: list[Identifier] = []
        head = html[:20000]  # signals appear early; keep it cheap
        for label, pattern in _EXPOSURE_SIGNALS:
            if pattern.search(head):
                logger.warning(
                    "EXPOSURE NOTED (detection only, no action taken): %s at %s",
                    label,
                    url,
                )
                notes.append(
                    Identifier(
                        EXPOSURE_NOTE,
                        label,
                        context=f"Observed passively at {url}; noted, not acted upon.",
                        heuristic=True,
                    )
                )
        return notes

    # ---- TLS capture ------------------------------------------------------

    def _capture_tls(self, url: str, stats: CrawlStats) -> list[Identifier]:
        """Capture and parse the TLS certificate for ``url``, if configured.

        Returns certificate-derived identifiers and records the certificate. A
        clearnet DNS name inside a hidden service's own certificate is the
        strongest passive attribution signal the toolkit can produce, so it is
        logged at WARNING even though nothing has gone wrong.
        """
        ev = self.cfg.evidence
        if not ev.capture_tls:
            return []
        scheme = urlsplit(url).scheme
        force = ev.probe_tls_on_http
        if scheme != "https" and not force:
            return []

        host = _host_of(url)
        if host in self._tls_seen:
            return []
        self._tls_seen.add(host)

        from .tls_probe import probe_url  # local import: PySocks only needed here

        try:
            observation = probe_url(self.cfg, url, force=force)
        except Exception as exc:  # noqa: BLE001 - never sink a crawl over TLS
            logger.warning("TLS capture failed for %s: %s", host, exc)
            return []
        if observation is None or not observation.ok or observation.certificate is None:
            return []

        stats.certificates_captured += 1
        self._pending_cert = observation
        idents = certificate_identifiers(observation.certificate, url)
        stats.clearnet_names_found += len(observation.certificate.clearnet_names())
        return idents

    # ---- favicon ----------------------------------------------------------

    def _capture_favicon(self, url: str, html: str) -> list[Identifier]:
        """Fetch and hash the page's favicon, if configured.

        Prefers the icon the page itself links to; falls back to the conventional
        ``/favicon.ico`` path. One extra GET per host, at most.
        """
        if not self.cfg.evidence.fetch_favicon:
            return []
        host = _host_of(url)
        if host in self._favicon_seen:
            return []
        self._favicon_seen.add(host)

        icon_url = None
        m = re.search(
            r'<link[^>]+rel=["\'][^"\']*\bicon\b[^"\']*["\'][^>]*>', html or "", re.I
        )
        if m:
            href = re.search(r'href=["\']([^"\']+)["\']', m.group(0), re.I)
            if href:
                icon_url = urljoin(url, href.group(1))
        if not icon_url:
            parts = urlsplit(url)
            icon_url = urlunsplit((parts.scheme, parts.netloc, "/favicon.ico", "", ""))

        result = self.session.get(icon_url)
        if not result.ok or not result.content:
            return []
        ident = favicon_identifier(result.content, icon_url)
        return [ident] if ident else []

    # ---- PGP --------------------------------------------------------------

    def _store_pgp_keys(self, source_id: int, text: str, stats: CrawlStats) -> None:
        """Parse every armored key on the page and store it by fingerprint."""
        for key in parse_pgp_keys(text):
            if self.storage.add_pgp_key(source_id, key):
                stats.pgp_keys_parsed += 1
                identities = ", ".join(
                    filter(None, [*key.names, *key.emails])
                ) or "no User ID"
                logger.info(
                    "PGP key %s (%s) parsed — identities: %s",
                    key.key_id, key.algorithm, identities,
                )

    # ---- frontier eligibility ---------------------------------------------

    def _eligible(self, url: str, seed_hosts: set[str]) -> bool:
        host = _host_of(url)
        if not host.endswith(".onion"):
            logger.debug("Skipping non-onion link: %s", url)
            return False
        if self.cfg.crawl.stay_on_seed_hosts and host not in seed_hosts:
            logger.debug("Skipping off-seed-host link: %s", url)
            return False
        return True

    # ---- main loop --------------------------------------------------------

    def crawl(self, seeds: list[str]) -> CrawlStats:
        stats = CrawlStats()
        seed_hosts = {_host_of(s) for s in seeds}
        frontier: deque[_FrontierItem] = deque(
            _FrontierItem(depth=0, url=s) for s in seeds
        )

        while frontier:
            if stats.pages_fetched >= self.cfg.crawl.max_pages:
                logger.info("Reached max_pages=%d; stopping.", self.cfg.crawl.max_pages)
                break

            item = frontier.popleft()
            norm = _normalize_url(item.url)
            if norm in self.visited:
                continue
            self.visited.add(norm)

            result = self.session.get(item.url)

            # Always record the source and (if we got bytes) a snapshot, even on
            # error, for a complete evidentiary trail.
            host = _host_of(item.url)
            parser = get_parser_for(item.url, self.extractor)
            title = None
            page_identifiers: list[Identifier] = []
            page_links: list[str] = []

            if result.content:
                snap_path, sha = self._save_snapshot(item.url, result.content)
            else:
                snap_path, sha = None, None

            parsed = None
            if result.ok and result.text:
                # Detect leaked secrets and redact them out of the working text
                # BEFORE anything else parses or stores it. The raw snapshot on
                # disk (saved above from result.content) keeps the plaintext as
                # the evidentiary record; nothing downstream — page documents,
                # identifier context windows, LLM enrichment — ever sees it.
                redacted_text, secret_ids = redact_secrets(result.text, item.url)

                parsed = parser.parse(item.url, redacted_text)
                title = parsed.title
                page_identifiers = list(parsed.identifiers)
                page_links = list(parsed.links)
                page_identifiers.extend(self._note_exposures(item.url, redacted_text))

                # Infrastructure evidence: banners from the response headers,
                # clearnet artifacts from the markup, the TLS certificate, and
                # the favicon hash. Each is a clearnet correlation key.
                page_identifiers.extend(header_identifiers(result.headers, item.url))
                page_identifiers.extend(page_artifacts(redacted_text, item.url))
                # Credential-shaped secrets leaked into the served content
                # (private keys, API tokens, dump lines). Passive, same posture
                # as exposure notes: flag what we were served, never fetch more.
                page_identifiers.extend(secret_ids)
                page_identifiers.extend(self._capture_tls(item.url, stats))
                page_identifiers.extend(self._capture_favicon(item.url, redacted_text))

                page_identifiers = self.extractor.dedup(page_identifiers)
                stats.pages_fetched += 1
            else:
                stats.pages_failed += 1
                logger.warning(
                    "Fetch unsuccessful for %s (status=%s, error=%s)",
                    item.url,
                    result.status,
                    result.error,
                )

            source_id = self.storage.add_source(
                url=item.url,
                host=host,
                site=parser.site_name,
                http_status=result.status,
                title=title,
                depth=item.depth,
                discovered_from=item.parent,
                response_headers=result.headers or None,
                final_url=result.final_url or None,
                tls_checked=self._pending_cert is not None,
            )

            # Attach the certificate captured for this page, then clear it so the
            # next page does not inherit it.
            if self._pending_cert is not None:
                self.storage.add_certificate(source_id, self._pending_cert)
                self._pending_cert = None
            if snap_path is not None:
                self.storage.add_snapshot(
                    source_id=source_id,
                    path=str(snap_path),
                    sha256=sha,
                    content_length=len(result.content),
                    content_type=result.content_type,
                )

            if page_identifiers:
                added = self.storage.add_identifiers(source_id, page_identifiers)
                stats.identifiers_added += added
                for ident in page_identifiers:
                    stats.bump_type(ident.type)
                    if ident.type == EXPOSURE_NOTE:
                        stats.exposures_noted += 1

            # Parse any armored PGP keys, and store text for the analysis layer.
            # Redaction only removes PRIVATE key blocks and credential shapes, so
            # armored PUBLIC keys survive and are still parsed here.
            if parsed is not None and result.text:
                self._store_pgp_keys(source_id, redacted_text, stats)

            if parsed is not None and self.cfg.evidence.store_documents:
                for handle, doc_text, posted_at in parsed.documents:
                    if doc_text and doc_text.strip():
                        self.storage.add_document(
                            source_id=source_id, text=doc_text,
                            handle=handle, posted_at=posted_at,
                            kind="post" if handle else "page",
                        )
                        stats.documents_stored += 1

            # Trust / vouch relationships a site-specific parser recognised.
            if parsed is not None:
                for from_handle, to_handle, weight, detail in parsed.trust_edges:
                    self.storage.add_actor_edge(
                        ("username_candidate", from_handle),
                        ("username_candidate", to_handle),
                        weight, "trust_link",
                        {"detail": detail, "source": item.url},
                    )

            # Record referral edges and expand the frontier.
            onion_links = [
                lk for lk in page_links if _host_of(lk).endswith(".onion")
            ]
            if onion_links:
                self.storage.add_links(source_id, item.url, onion_links)
                stats.links_discovered += len(onion_links)

            if self.cfg.crawl.expand_frontier and item.depth < self.cfg.crawl.max_depth:
                for lk in onion_links:
                    if not self._eligible(lk, seed_hosts):
                        continue
                    if _normalize_url(lk) in self.visited:
                        continue
                    frontier.append(
                        _FrontierItem(depth=item.depth + 1, url=lk, parent=item.url)
                    )

        # Merge in the actual DB type counts for an accurate final summary.
        stats.identifiers_by_type = self.storage.counts_by_type()

        if self.cfg.evidence.correlate_after_crawl:
            # Correlation is pure analysis over what was just collected: no
            # network, no contact with any target.
            from .correlation import CorrelationEngine

            findings = CorrelationEngine(self.storage).run(persist=True)
            if findings:
                logger.info(
                    "Clearnet correlation produced %d finding(s); "
                    "strongest: %s -> %s at %.2f",
                    len(findings), findings[0].onion_host,
                    findings[0].clearnet, findings[0].confidence,
                )
        return stats
