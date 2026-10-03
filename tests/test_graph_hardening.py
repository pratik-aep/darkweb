"""Regression tests for actor-graph over-merging.

These pin the two failure modes that made the resolver fuse unrelated operators:
a directory page that lists many people's keys, and a shared boilerplate node
(a market's footer contact) that bridged every vendor into one phantom actor.
They also guard the flip side — a genuine single-vendor profile must still
resolve — so the hardening cannot be "fixed" by simply linking nothing.
"""
from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from darkosint.extractors import Identifier
from darkosint.graph import ActorGraph
from darkosint.storage import Storage

MARKET = "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm.onion"


def _fpr(i: int) -> str:
    return hashlib.sha1(f"vendor{i}".encode()).hexdigest().upper()


def _pgp_members(actor) -> list[str]:
    return [v for t, v in actor.members if t == "pgp_fingerprint"]


def test_directory_page_does_not_merge_unrelated_keys():
    """Fifteen vendors' keys on one index page are a listing, not one actor."""
    with tempfile.TemporaryDirectory() as tmp:
        with Storage(Path(tmp) / "d.db") as storage:
            src = storage.add_source(
                url=f"http://{MARKET}/vendors", host=MARKET,
                site="generic", http_status=200,
            )
            storage.add_identifiers(
                src, [Identifier("pgp_fingerprint", _fpr(i)) for i in range(15)]
            )
            actors = ActorGraph(storage).build()

            # No cluster may fuse two distinct keys off a shared page alone.
            assert all(len(_pgp_members(a)) <= 1 for a in actors), (
                "a directory page merged unrelated keys into one actor"
            )


def test_shared_footer_contact_does_not_merge_a_whole_market():
    """A support email in every vendor's footer must not bridge their keys."""
    with tempfile.TemporaryDirectory() as tmp:
        with Storage(Path(tmp) / "f.db") as storage:
            for i in range(5):
                src = storage.add_source(
                    url=f"http://{MARKET}/vendor/{i}", host=MARKET,
                    site="generic", http_status=200,
                )
                storage.add_identifiers(src, [
                    Identifier("pgp_fingerprint", _fpr(i)),
                    Identifier("btc_address", f"1Vendor{i}WalletWalletWalletWa"),
                    Identifier("email", "support@market.example"),
                ])
            actors = ActorGraph(storage).build()

            # The shared email is boilerplate; no actor may hold two vendors' keys.
            assert all(len(_pgp_members(a)) <= 1 for a in actors), (
                "a shared footer contact merged separate vendors into one actor"
            )


def test_two_keys_sharing_only_a_contact_stay_separate():
    """Two distinct keys bridged only by a shared email (on too few pages for
    boilerplate damping) must still be refused a merge at union time — two
    cryptographic identities are not one person on weak evidence alone."""
    with tempfile.TemporaryDirectory() as tmp:
        with Storage(Path(tmp) / "c.db") as storage:
            for i in range(2):
                src = storage.add_source(
                    url=f"http://{MARKET}/seller/{i}", host=MARKET,
                    site="generic", http_status=200,
                )
                storage.add_identifiers(src, [
                    Identifier("pgp_fingerprint", _fpr(i)),
                    Identifier("email", "contact@shared.example"),
                ])
            actors = ActorGraph(storage).build()
            assert all(len(_pgp_members(a)) <= 1 for a in actors), (
                "two distinct keys were fused by a shared contact on weak evidence"
            )


def test_a_genuine_single_vendor_profile_still_resolves():
    """The hardening must not suppress a real key+wallet+handle profile."""
    with tempfile.TemporaryDirectory() as tmp:
        with Storage(Path(tmp) / "p.db") as storage:
            src = storage.add_source(
                url=f"http://{MARKET}/vendor/solo", host=MARKET,
                site="generic", http_status=200,
            )
            storage.add_identifiers(src, [
                Identifier("pgp_fingerprint", _fpr(99)),
                Identifier("btc_address", "1SoloVendorWalletWalletWalletWa"),
                Identifier("username_candidate", "solovendor", heuristic=True),
            ])
            actors = ActorGraph(storage).build()

            anchored = [a for a in actors if _fpr(99) in _pgp_members(a)]
            assert anchored, "a legitimate single-vendor profile failed to resolve"
            members = dict(anchored[0].members)
            assert "btc_address" in members and "username_candidate" in members


def test_confidence_reflects_the_weakest_link_not_the_best():
    """A cluster held together by a weak edge must not inherit a strong edge's
    confidence: the wallet three hops out cannot ride the key's certainty."""
    with tempfile.TemporaryDirectory() as tmp:
        with Storage(Path(tmp) / "w.db") as storage:
            src = storage.add_source(
                url=f"http://{MARKET}/vendor/chain", host=MARKET,
                site="generic", http_status=200,
            )
            # A key + email (near-certain via co-occurrence on a 2-item page)
            # plus a wallet that only attaches through a crowded, weaker link.
            storage.add_identifiers(src, [
                Identifier("pgp_fingerprint", _fpr(7)),
                Identifier("email", "vendor7@mail.example"),
            ])
            src2 = storage.add_source(
                url=f"http://{MARKET}/vendor/chain2", host=MARKET,
                site="generic", http_status=200,
            )
            storage.add_identifiers(src2, [
                Identifier("pgp_fingerprint", _fpr(7)),
                Identifier("btc_address", "1Chain7WalletWalletWalletWallet"),
                Identifier("username_candidate", "h1", heuristic=True),
                Identifier("username_candidate", "h2", heuristic=True),
                Identifier("username_candidate", "h3", heuristic=True),
            ])
            actors = ActorGraph(storage).build()
            anchored = next(a for a in actors if _fpr(7) in _pgp_members(a))

            # The wallet's per-member attachment must sit below the confidence
            # the tightly-bound key+email core would score on its own.
            wallet = ("btc_address", "1Chain7WalletWalletWalletWallet")
            assert wallet in anchored.attachment
            assert anchored.attachment[wallet] < 0.9
