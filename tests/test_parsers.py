"""Unit tests for the parser layer and registry."""
from darkosint.extractors import BTC_ADDRESS, ONION_URL
from darkosint.parsers import GenericParser, get_parser_for, registered_sites
from darkosint.parsers.example_market import ExampleMarketParser

DDG_ONION = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"

SAMPLE_HTML = f"""
<html><head><title>Test Market</title></head>
<body>
  <p>Pay to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</p>
  <a href="http://{DDG_ONION}/mirror">mirror</a>
  <script>var x = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 should be ignored";</script>
</body></html>
"""


def test_registry_falls_back_to_generic():
    parser = get_parser_for("http://unknownhost.onion/")
    assert isinstance(parser, GenericParser)
    assert "generic" in registered_sites()


def test_example_market_matches_its_host():
    from darkosint.parsers.example_market import _EXAMPLE_HOST

    parser = get_parser_for(f"http://{_EXAMPLE_HOST}/listing")
    assert isinstance(parser, ExampleMarketParser)


def test_generic_parse_extracts_and_finds_links():
    parser = get_parser_for("http://target.onion/")
    result = parser.parse("http://target.onion/", SAMPLE_HTML)

    assert result.title == "Test Market"
    btc = {i.value for i in result.identifiers if i.type == BTC_ADDRESS}
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in btc
    # <script> content is stripped, so the address inside it is not extracted.
    assert "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" not in btc

    # The onion link is discovered both from text and the anchor href.
    assert any(DDG_ONION in lk for lk in result.links)
    onion_ids = {i.value for i in result.identifiers if i.type == ONION_URL}
    assert any(DDG_ONION in v for v in onion_ids)
