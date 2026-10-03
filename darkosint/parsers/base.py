"""Base parser interface.

Marketplace and forum HTML differ wildly and change often, so parsing is
deliberately per-site: a small ``BaseParser`` contract that each site subclass
overrides. There is intentionally NO universal parser — the generic parser is a
best-effort fallback, and real targets get their own subclass.

A parser's job is narrow and passive: given already-fetched HTML, return the
identifiers found and the onion links to consider for the frontier. Parsers
never fetch, never write to disk, and never act on anything they observe.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from ..extractors import Identifier, IdentifierExtractor, ONION_URL

logger = logging.getLogger("darkosint.parsers")

try:
    from bs4 import BeautifulSoup

    _HAVE_BS4 = True
except ImportError:  # pragma: no cover - environment dependent
    BeautifulSoup = None  # type: ignore
    _HAVE_BS4 = False
    # Without bs4 the parser cannot strip <script>/<style>, so extraction runs
    # over raw markup and manufactures false positives out of inline JavaScript
    # (a wallet address inside a <script> block gets reported as if it were
    # published on the page). That is a silent accuracy loss, so it is announced
    # loudly once at import rather than degrading quietly.
    logger.warning(
        "beautifulsoup4 is NOT installed. Extraction will run over raw HTML "
        "including <script>/<style> content, which produces FALSE POSITIVES and "
        "cannot resolve anchor hrefs. Install it with `pip install beautifulsoup4` "
        "before trusting any output from this run."
    )


@dataclass
class ParseResult:
    """What a parser returns for one page.

    ``documents`` and ``trust_edges`` are how a site-specific parser feeds the
    analysis layer. The generic parser cannot fill them — attributing text to an
    author, or reading a feedback table, requires knowing the site's markup — so
    they default to empty and a per-site subclass populates them.
    """

    identifiers: list[Identifier] = field(default_factory=list)
    links: list[str] = field(default_factory=list)  # absolute onion URLs
    title: str | None = None

    #: ``(handle, text, posted_at)`` — authored samples for stylometry. ``handle``
    #: may be None for unattributed page text; ``posted_at`` is ISO-8601 or None.
    documents: list[tuple[str | None, str, str | None]] = field(default_factory=list)

    #: ``(from_handle, to_handle, weight, detail)`` — vouch / feedback / trust
    #: relationships, which become trust edges in the actor graph.
    trust_edges: list[tuple[str, str, float, str]] = field(default_factory=list)

    #: Set when the page could not be parsed as richly as intended.
    degraded: bool = not _HAVE_BS4


class BaseParser:
    """Subclass this per site. Override :meth:`matches` and :meth:`parse`.

    The default :meth:`parse` runs the generic identifier extraction over the
    page's visible text plus anchor hrefs — a sensible baseline that subclasses
    can call via ``super().parse(...)`` and then augment with site-specific logic.
    """

    #: Human-readable site/parser name, recorded on each source row.
    site_name: str = "base"

    def __init__(self, extractor: IdentifierExtractor | None = None):
        self.extractor = extractor or IdentifierExtractor()

    # ---- selection --------------------------------------------------------

    @classmethod
    def matches(cls, url: str) -> bool:
        """Return True if this parser should handle ``url``. Override per site."""
        return False

    # ---- helpers for subclasses ------------------------------------------

    @staticmethod
    def make_soup(html: str):
        """Parse HTML with BeautifulSoup if available, else return None."""
        if not _HAVE_BS4:
            return None
        return BeautifulSoup(html, "html.parser")

    @staticmethod
    def visible_text(html: str) -> str:
        """Extract visible text, dropping script/style/noscript noise."""
        if not _HAVE_BS4:
            return html  # fall back to raw HTML; extractors still work on it
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(["script", "style", "noscript", "template"]):
            tag.decompose()
        return soup.get_text(separator=" ")

    @staticmethod
    def anchor_links(html: str, base_url: str) -> list[str]:
        """Absolute .onion links from <a href> attributes."""
        if not _HAVE_BS4:
            return []
        soup = BeautifulSoup(html, "html.parser")
        out: list[str] = []
        for a in soup.find_all("a", href=True):
            absolute = urljoin(base_url, a["href"])
            host = (urlsplit(absolute).hostname or "").lower()
            if host.endswith(".onion"):
                out.append(absolute)
        return out

    # ---- main entrypoint --------------------------------------------------

    def parse(self, url: str, html: str) -> ParseResult:
        """Default: extract identifiers from text + collect onion links.

        Onion links are gathered from both the visible text and the anchor
        hrefs. Links that appear only in an ``href`` (never in visible text)
        are still recorded as ONION_URL identifiers, so the identifiers table
        captures every referenced onion, not just those written in prose.
        """
        text = self.visible_text(html)
        identifiers = self.extractor.extract(text)

        text_onions = {i.value for i in identifiers if i.type == ONION_URL}
        anchor_onions = self.anchor_links(html, url)
        for link in anchor_onions:
            if link not in text_onions:
                identifiers.append(
                    Identifier(ONION_URL, link, context=f"<a href> on {url}")
                )
        identifiers = self.extractor.dedup(identifiers)

        links = sorted(text_onions | set(anchor_onions))

        title = None
        soup = self.make_soup(html)
        if soup is not None and soup.title and soup.title.string:
            title = soup.title.string.strip()

        result = ParseResult(identifiers=identifiers, links=links, title=title)
        # Record the page text as an unattributed document: it feeds temporal
        # analysis, LLM claim extraction, and (once a site parser attributes it
        # to a handle) the stylometry corpus.
        if text and text.strip():
            result.documents.append((None, text.strip(), None))
        return result
