"""Generic fallback parser.

Used for any URL that no site-specific parser claims. It runs the default
:meth:`BaseParser.parse` (visible-text extraction + anchor harvesting) and then,
when the page looks like stock forum software (phpBB and its many derivatives),
recovers per-author post text so authorship and timezone analysis work on real
crawls — not only on hand-written site parsers. When the forum structure is not
recognised it changes nothing, keeping the anonymous-page fallback.
"""
from __future__ import annotations

from ..extractors import Identifier, USERNAME
from .base import BaseParser
from .forum import extract_posts, extract_quote_edges


class GenericParser(BaseParser):
    site_name = "generic"

    @classmethod
    def matches(cls, url: str) -> bool:
        # The registry falls back to this explicitly; it never self-selects.
        return False

    def parse(self, url: str, html: str):
        result = super().parse(url, html)

        soup = self.make_soup(html)
        if soup is None:
            return result

        # Quote edges first: extract_posts strips <blockquote> from bodies, so
        # read the reply relationships before that mutation removes them.
        quote_edges = extract_quote_edges(soup, url)
        posts = extract_posts(soup)
        if not posts:
            return result  # not a recognised forum: keep the anonymous page doc

        # Replace the anonymous whole-page document with attributed post samples,
        # which is what makes stylometry and temporal inference possible.
        result.documents = posts
        result.trust_edges.extend(quote_edges)

        handles = {h for h, _, _ in posts}
        result.identifiers = self.extractor.dedup(result.identifiers + [
            Identifier(USERNAME, h, context=f"forum post author on {url}", heuristic=True)
            for h in handles
        ])
        return result
