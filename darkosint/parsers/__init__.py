"""Parser registry.

Register site-specific parsers here in priority order. ``get_parser_for(url)``
returns the first parser whose :meth:`matches` claims the URL, falling back to
the :class:`GenericParser`. Add a new target by writing a ``BaseParser``
subclass (see ``example_market.py``) and appending it to ``_REGISTRY``.
"""
from __future__ import annotations

from ..extractors import IdentifierExtractor
from .base import BaseParser, ParseResult
from .example_market import ExampleMarketParser
from .generic import GenericParser

# Order matters: more specific parsers first, generic fallback handled separately.
_REGISTRY: list[type[BaseParser]] = [
    ExampleMarketParser,
    # ... add more site-specific parsers here ...
]


def get_parser_for(url: str, extractor: IdentifierExtractor | None = None) -> BaseParser:
    """Return an instantiated parser appropriate for ``url``."""
    for parser_cls in _REGISTRY:
        if parser_cls.matches(url):
            return parser_cls(extractor)
    return GenericParser(extractor)


def registered_sites() -> list[str]:
    return [p.site_name for p in _REGISTRY] + [GenericParser.site_name]


__all__ = [
    "BaseParser",
    "ParseResult",
    "GenericParser",
    "ExampleMarketParser",
    "get_parser_for",
    "registered_sites",
]
