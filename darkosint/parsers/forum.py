"""Attributed-post extraction for common forum software (phpBB & look-alikes).

The whole analysis layer's authorship and timezone work needs text *tied to the
handle that wrote it*, and the generic parser can only record a page's text as
anonymous. Most onion forums, though, run stock software (phpBB most of all)
whose post markup is predictable, so a handful of selectors recovers
``(handle, body, posted_at)`` per post — passively, from already-fetched HTML.

This is deliberately conservative: it returns nothing rather than guess when the
structure is not recognised, so the generic parser keeps its anonymous-page
fallback and nothing downstream is fed a mis-attributed sample.
"""
from __future__ import annotations

import re

# Author link classes phpBB (and its skins/derivatives) use.
_AUTHOR_SEL = ".author .username, .author .username-coloured, a.username, a.username-coloured"
_BODY_SEL = ".content, .postbody .content, .post_body, .message-body .bbWrapper"

_ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:[+-]\d{2}:\d{2}|Z)?")


def _posts(soup):
    """Outermost post containers only, so nested markup is not counted twice."""
    return (soup.select("div.post")
            or soup.select("div.postbody")
            or soup.select("article.message"))


def _clean_handle(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()[:32]


def extract_posts(soup) -> list[tuple[str, str, str | None]]:
    """Return ``[(handle, body_text, posted_at_iso_or_None)]`` for a forum page.

    Quoted text (``<blockquote>``) is stripped from each body so a quote of
    another member does not contaminate the author's stylometric profile.
    """
    if soup is None:
        return []
    out: list[tuple[str, str, str | None]] = []
    for post in _posts(soup):
        author_el = post.select_one(_AUTHOR_SEL)
        body_el = post.select_one(_BODY_SEL)
        if not (author_el and body_el):
            continue
        handle = _clean_handle(author_el.get_text())
        if not handle:
            continue

        # Drop quoted material before reading the author's own words.
        for q in body_el.select("blockquote, .quote, .bbCodeBlock"):
            q.decompose()
        body = re.sub(r"\s+", " ", body_el.get_text(separator=" ")).strip()
        if len(body) < 20:  # too short to be a usable authorship sample
            continue

        posted_at = None
        time_el = post.select_one("time")
        if time_el is not None:
            stamp = time_el.get("datetime") or time_el.get_text(strip=True)
            m = _ISO.search(stamp or "")
            if m:
                posted_at = m.group(0).replace(" ", "T")
        out.append((handle, body, posted_at))
    return out


def extract_quote_edges(soup, url: str) -> list[tuple[str, str, float, str]]:
    """Reply/quote relationships between handles → weak trust_link edges.

    phpBB renders a quoted member as ``<cite>bob wrote:</cite>`` inside the
    quoting post, which is a genuine interaction between two handles (weaker than
    co-authorship, so it links without merging).
    """
    if soup is None:
        return []
    edges: list[tuple[str, str, float, str]] = []
    for post in _posts(soup):
        author_el = post.select_one(_AUTHOR_SEL)
        if not author_el:
            continue
        frm = _clean_handle(author_el.get_text())
        if not frm:
            continue
        for cite in post.select("blockquote cite, .quote cite, .bbCodeBlock .attribution"):
            quoted = _clean_handle(re.sub(r"\bwrote\b.*$", "", cite.get_text(), flags=re.I))
            if quoted and quoted != frm:
                edges.append((frm, quoted, 0.28, f"quoted/replied on {url}"))
    return edges
