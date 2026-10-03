"""Crawler wiring tests, with a stubbed session in place of Tor.

Verifies that every evidence class actually reaches storage: response-header
banners, clearnet artifacts from markup, parsed PGP keys, page documents, TLS
certificates, and the passive exposure notes. A real Tor crawl cannot run in CI,
but the orchestration between fetch, parse, capture and persist can.
"""
from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from darkosint.config import Config
from darkosint.crawler import Crawler
from darkosint.storage import Storage
from darkosint.tor_session import FetchResult

ONION = "testmarkettestmarkettestmarkettestmarkettestmarketaaaaaa.onion"

PGP_BLOCK = """-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: EB85 BB5F A33A 75E1 5E94  4E63 F231 550C 4F47 E38E

xjMEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U
b7O1u13OOARcRwTpEgorBgEEAZdVAQUBAQdAQv8GIa2rSTzgqbXCpDDYMiKRVitC
sy203x3sE9+eviIDAQgHwngEGBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUC
XEcE6QIbDAAKCRDyMVUMT0fjjlnQAQDFHUs6TIcxrNTtEZFjUFm1M0PJ1Dng/cDW
4xN80fsn0QEA22Kr7VkCjeAEC08VSTeV+QFsmz55/lntWkwYWhmvOgE=
=qReC
-----END PGP PUBLIC KEY BLOCK-----"""

PAGE = f"""<html><head><title>Test Vendor</title>
<script>gtag('config','G-TESTID1234');</script>
</head><body>
<h1>Apache Server Status for testhost</h1>
<p>Contact: vendor@mail.test — pay to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</p>
<img src="https://assets.vendor-origin.test/logo.png">
<pre>{PGP_BLOCK}</pre>
</body></html>"""


@dataclass
class StubSession:
    """Stands in for TorSession: serves one canned page, records requests."""

    requested: list[str] = field(default_factory=list)

    def get(self, url: str) -> FetchResult:
        self.requested.append(url)
        body = PAGE.encode("utf-8")
        return FetchResult(
            url=url, ok=True, status=200, text=PAGE, content=body,
            content_type="text/html", final_url=url,
            headers={
                "Server": "Apache/2.4.41 (Ubuntu)",
                "X-Powered-By": "PHP/7.4.3",
                "ETag": '"5f2a-61b2c3d4"',
                "Content-Type": "text/html",
            },
        )


def _crawl(tmp: Path, cfg: Config | None = None):
    cfg = cfg or Config().with_overrides(**{
        "crawl.max_pages": 1,
        "crawl.max_depth": 0,
        "evidence.capture_tls": False,      # no socket available in tests
        "evidence.correlate_after_crawl": False,
    })
    session = StubSession()
    storage = Storage(tmp / "osint.db")
    crawler = Crawler(cfg, session, storage, tmp)
    stats = crawler.crawl([f"http://{ONION}/vendor"])
    return stats, storage, session


def test_crawl_stores_source_snapshot_and_headers():
    with tempfile.TemporaryDirectory() as tmp:
        stats, storage, _ = _crawl(Path(tmp))
        with storage:
            assert stats.pages_fetched == 1
            sources = storage.list_sources()
            assert len(sources) == 1

            rows = storage.sources_with_headers()
            assert len(rows) == 1, "response headers were not persisted"
            headers = json.loads(rows[0]["response_headers"])
            # Regression: headers used to be discarded except Content-Type,
            # which threw away the whole "default service banner" evidence class.
            assert headers["Server"] == "Apache/2.4.41 (Ubuntu)"

            snaps = storage.snapshots_for(sources[0]["id"])
            assert len(snaps) == 1 and snaps[0]["sha256"]
            assert Path(snaps[0]["path"]).exists()


def test_crawl_extracts_banner_identifiers_from_headers():
    with tempfile.TemporaryDirectory() as tmp:
        _, storage, _ = _crawl(Path(tmp))
        with storage:
            by_type = storage.counts_by_type()
            assert by_type.get("server_banner")
            assert by_type.get("powered_by")
            assert by_type.get("etag")
            banners = {r["value"] for r in storage.find_by_type("server_banner")}
            assert "Apache/2.4.41 (Ubuntu)" in banners


def test_crawl_extracts_clearnet_artifacts_from_markup():
    with tempfile.TemporaryDirectory() as tmp:
        _, storage, _ = _crawl(Path(tmp))
        with storage:
            analytics = {r["value"] for r in storage.find_by_type("analytics_id")}
            assert "G-TESTID1234" in analytics
            domains = {r["value"] for r in storage.find_by_type("clearnet_domain")}
            assert "assets.vendor-origin.test" in domains


def test_crawl_parses_and_stores_pgp_keys():
    """The key must be stored by fingerprint, not merely hashed as a blob."""
    with tempfile.TemporaryDirectory() as tmp:
        stats, storage, _ = _crawl(Path(tmp))
        with storage:
            assert stats.pgp_keys_parsed == 1
            keys = storage.pgp_keys()
            assert len(keys) == 1
            assert keys[0]["fingerprint"] == "EB85BB5FA33A75E15E944E63F231550C4F47E38E"
            assert keys[0]["key_id"] == "F231550C4F47E38E"
            # The fingerprint is also an identifier, so it pivots across sources.
            fprs = {r["value"] for r in storage.find_by_type("pgp_fingerprint")}
            assert "EB85BB5FA33A75E15E944E63F231550C4F47E38E" in fprs


def test_crawl_stores_page_text_as_a_document():
    with tempfile.TemporaryDirectory() as tmp:
        stats, storage, _ = _crawl(Path(tmp))
        with storage:
            assert stats.documents_stored == 1
            docs = storage.documents(with_handle=False)
            assert len(docs) == 1
            assert "Test Vendor" in docs[0]["text"] or "pay to" in docs[0]["text"]


def test_crawl_notes_exposures_without_probing():
    """An exposed endpoint is recorded, and nothing extra is requested."""
    with tempfile.TemporaryDirectory() as tmp:
        stats, storage, session = _crawl(Path(tmp))
        with storage:
            assert stats.exposures_noted >= 1
            notes = {r["value"] for r in storage.find_by_type("exposure_note")}
            assert "apache_server_status" in notes
            # Exactly one request: the page. No probe, no follow-up.
            assert session.requested == [f"http://{ONION}/vendor"]


def test_favicon_is_not_fetched_unless_enabled():
    """The extra GET is opt-in, so the default run must not make it."""
    with tempfile.TemporaryDirectory() as tmp:
        _, storage, session = _crawl(Path(tmp))
        with storage:
            assert not any("favicon" in u for u in session.requested)


def test_favicon_fetch_when_enabled_produces_a_shodan_hash():
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config().with_overrides(**{
            "crawl.max_pages": 1, "crawl.max_depth": 0,
            "evidence.capture_tls": False, "evidence.fetch_favicon": True,
            "evidence.correlate_after_crawl": False,
        })
        _, storage, session = _crawl(Path(tmp), cfg)
        with storage:
            assert any("/favicon.ico" in u for u in session.requested)
            assert storage.counts_by_type().get("favicon_mmh3")


def test_correlation_runs_automatically_when_configured():
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config().with_overrides(**{
            "crawl.max_pages": 1, "crawl.max_depth": 0,
            "evidence.capture_tls": False,
            "evidence.correlate_after_crawl": True,
        })
        _, storage, _ = _crawl(Path(tmp), cfg)
        with storage:
            findings = storage.correlations()
            # The page references a clearnet domain, which is candidate
            # generation, not attribution — so it must be recorded, and recorded
            # weakly. Nothing here justifies a confident claim.
            assert findings, "the automatic correlation pass did not run"
            by_domain = {r["clearnet"]: r for r in findings}
            assert "assets.vendor-origin.test" in by_domain
            weak = by_domain["assets.vendor-origin.test"]
            assert weak["method"] == "clearnet_reference"
            assert weak["confidence"] < 0.3, (
                "a merely referenced domain must not score as attribution"
            )
            assert not [r for r in findings if r["confidence"] > 0.5]
