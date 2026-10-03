"""Unit tests for identifier extraction and validation."""
from darkosint.extractors import (
    BTC_ADDRESS,
    EMAIL,
    ETH_ADDRESS,
    IdentifierExtractor,
    ONION_URL,
    PGP_BLOCK,
    PGP_FINGERPRINT,
    USERNAME,
    XMPP,
    XMR_ADDRESS,
    base58check_valid,
    bech32_valid,
    onion_hosts,
)

DDG_ONION = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"


def types(items):
    return {i.type for i in items}


def values_of(items, type_):
    return {i.value for i in items if i.type == type_}


def test_btc_base58_checksum_validation():
    # Genesis-block address (valid) vs. a checksum-corrupted variant (invalid).
    assert base58check_valid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    assert not base58check_valid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
    assert base58check_valid("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")  # P2SH


def test_bech32_checksum_validation():
    assert bech32_valid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    # taproot / bech32m
    assert bech32_valid(
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
    )
    assert not bech32_valid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")  # bad cksum


def test_extracts_valid_btc_rejects_garbage():
    ex = IdentifierExtractor()
    text = (
        "Pay 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or "
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 . "
        "Not an address: 1ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ."
    )
    got = values_of(ex.extract(text), BTC_ADDRESS)
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in got
    assert "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" in got
    assert not any(v.startswith("1ZZZ") for v in got)  # checksum-rejected


def test_extracts_eth_and_xmr():
    ex = IdentifierExtractor()
    eth = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
    xmr = (
        "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7Sq"
        "SsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A"
    )
    items = ex.extract(f"eth {eth} monero {xmr}")
    assert eth in values_of(items, ETH_ADDRESS)
    assert xmr in values_of(items, XMR_ADDRESS)


def test_pgp_block_and_fingerprint():
    ex = IdentifierExtractor()
    block = (
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
        "mQENBFxyz123FAKEbase64content==\n"
        "-----END PGP PUBLIC KEY BLOCK-----"
    )
    fpr = "1234 5678 90AB CDEF 1234 5678 90AB CDEF 1234 5678"
    items = ex.extract(f"{block}\nFingerprint: {fpr}")
    assert types(items) & {PGP_BLOCK}
    block_vals = values_of(items, PGP_BLOCK)
    assert any(v.startswith("sha256:") for v in block_vals)
    fprs = values_of(items, PGP_FINGERPRINT)
    assert "1234567890ABCDEF1234567890ABCDEF12345678" in fprs


def test_email_vs_xmpp():
    ex = IdentifierExtractor()
    text = "General inbox admin@shop.example is separate. Contact xmpp:dealer@example.org too."
    items = ex.extract(text)
    assert "admin@shop.example" in values_of(items, EMAIL)
    assert "dealer@example.org" in values_of(items, XMPP)


def test_onion_extraction_and_hosts():
    ex = IdentifierExtractor()
    text = f"Mirror at http://{DDG_ONION}/search and also {DDG_ONION}."
    items = ex.extract(text)
    onions = values_of(items, ONION_URL)
    assert any(DDG_ONION in v for v in onions)
    assert f"{DDG_ONION}" in onion_hosts(text)


def test_username_heuristics_flagged():
    ex = IdentifierExtractor()
    items = ex.extract("Deals by @shadowvendor . vendor: darkseller99 ships fast.")
    handles = values_of(items, USERNAME)
    assert "shadowvendor" in handles
    assert "darkseller99" in handles
    # Username candidates must always be flagged heuristic (analyst review).
    assert all(i.heuristic for i in items if i.type == USERNAME)


def test_onion_not_misread_as_crypto():
    # A 56-char onion host should not leak into BTC/XMR/email results.
    ex = IdentifierExtractor()
    items = ex.extract(f"visit {DDG_ONION}")
    assert not (types(items) & {BTC_ADDRESS, XMR_ADDRESS, EMAIL})


def test_dedup_by_type_value():
    ex = IdentifierExtractor()
    items = ex.extract("a@b.com a@b.com a@b.com")
    assert len(values_of(items, EMAIL)) == 1
