"""Example site-specific parser (TEMPLATE).

This demonstrates the intended pattern for adding a real target: subclass
``BaseParser``, claim URLs in :meth:`matches`, and override :meth:`parse` to pull
structured fields out of that site's specific HTML *before* delegating to the
generic text pass for everything else.

It is also the reference for the two things **only** a site-specific parser can
supply, and which the whole analysis layer depends on:

``result.documents``
    Post text attributed to the handle that wrote it. The generic parser can only
    record a page's text as anonymous, and stylometric attribution needs text
    tied to an author — so without a parser like this one, stylometry has no
    corpus to work with.
``result.trust_edges``
    Vouch / feedback / referral relationships between handles, which become
    ``trust_link`` edges in the actor graph.

The selectors below are illustrative placeholders for a fictional marketplace.
Point ``matches`` at a real onion host and adjust the selectors to that site's
DOM to use it for real. Collection stays passive: this only reads already-fetched
HTML.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..extractors import Identifier, USERNAME
from .base import BaseParser, ParseResult

# Replace with the real target host to activate this parser.
_EXAMPLE_HOST = "examplemarketplaceonionhost234567abcdefghijklmnopqrstuvwx.onion"

_RE_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?")


class ExampleMarketParser(BaseParser):
    site_name = "example_market"

    @classmethod
    def matches(cls, url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        return host == _EXAMPLE_HOST

    def parse(self, url: str, html: str) -> ParseResult:
        # 1) Start from the generic pass (identifiers from text + onion links).
        result = super().parse(url, html)

        soup = self.make_soup(html)
        if soup is None:
            return result

        # 2) Site-specific structured extraction. Because we know this site's DOM,
        #    vendor handles here are higher-confidence than the generic heuristic
        #    — but they are still flagged for analyst review, never ground truth.
        extra: list[Identifier] = []
        for card in soup.select("div.vendor-card"):
            name_el = card.select_one(".vendor-name")
            if not name_el:
                continue
            handle = name_el.get_text(strip=True)
            if handle:
                extra.append(
                    Identifier(
                        USERNAME,
                        handle,
                        context=f"vendor-card on {url}",
                        heuristic=True,
                    )
                )

        # 3) Attributed post text -> the stylometry corpus.
        #    Replace the generic page-level document with per-author samples,
        #    which is what makes authorship attribution possible at all.
        attributed: list[tuple[str | None, str, str | None]] = []
        for post in soup.select("div.post"):
            author_el = post.select_one(".post-author")
            body_el = post.select_one(".post-body")
            if not (author_el and body_el):
                continue
            handle = author_el.get_text(strip=True)
            body = body_el.get_text(separator=" ", strip=True)
            if not (handle and body):
                continue

            posted_at = None
            time_el = post.select_one("time")
            if time_el is not None:
                stamp = time_el.get("datetime") or time_el.get_text(strip=True)
                m = _RE_ISO_DATE.search(stamp or "")
                if m:
                    posted_at = m.group(0).replace(" ", "T")

            attributed.append((handle, body, posted_at))

        if attributed:
            # Drop the anonymous whole-page document in favour of attributed text.
            result.documents = attributed

        # 4) Trust / feedback relationships -> trust_link edges in the actor graph.
        for row in soup.select("div.feedback-row"):
            from_el = row.select_one(".feedback-from")
            to_el = row.select_one(".feedback-to")
            if not (from_el and to_el):
                continue
            buyer = from_el.get_text(strip=True)
            vendor = to_el.get_text(strip=True)
            if not (buyer and vendor) or buyer == vendor:
                continue
            rating_el = row.select_one(".feedback-rating")
            rating = (rating_el.get_text(strip=True) if rating_el else "") or "unrated"
            # A single transaction is weak evidence of a shared operator; it is
            # a relationship, which is what the graph should record. Weight it
            # below the co-occurrence floor so it links without merging.
            result.trust_edges.append(
                (buyer, vendor, 0.30, f"feedback ({rating}) on {url}")
            )

        result.identifiers = self.extractor.dedup(result.identifiers + extra)
        return result
