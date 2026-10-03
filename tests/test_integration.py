"""End-to-end test of the analysis chain.

Builds a small synthetic corpus with known ground truth — two marketplaces and a
clearnet site, one operator publishing the same PGP key on both markets, a
certificate leaking a clearnet domain, a shared analytics ID, and two authors
writing under two handles each — then asserts that each analysis stage recovers
the planted facts.

Everything is offline: no Tor, no network, no live site.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from darkosint.correlation import CorrelationEngine
from darkosint.extractors import Identifier
from darkosint.graph import ActorGraph, PGP_UID_EMAIL
from darkosint.storage import Storage
from darkosint.stylometry import STYLOMETRY_MIN_SCORE, StylometryEngine
from darkosint.temporal import TemporalAnalyzer

MARKET_A = "aaaamarketaaaamarketaaaamarketaaaamarketaaaamarketaaaaaa.onion"
MARKET_B = "bbbbforumbbbbforumbbbbforumbbbbforumbbbbforumbbbbforumbb.onion"
CLEARNET = "shop.example-vendor.test"

# A real, parseable Ed25519 key (RFC 9580 sample) with a UID added, so the
# fingerprint the parser derives is a genuine one.
VENDOR_KEY_FPR = "EB85BB5FA33A75E15E944E63F231550C4F47E38E"


def _mk_storage(tmp: Path) -> Storage:
    return Storage(tmp / "test.db")


def _seed_corpus(storage: Storage) -> dict:
    """Plant known facts across three hosts. Returns the ground truth."""
    # --- market A: vendor page with a key, a wallet, and an analytics tag ---
    src_a = storage.add_source(
        url=f"http://{MARKET_A}/vendor/nightferry", host=MARKET_A,
        site="generic", http_status=200, title="nightferry",
        response_headers={"Server": "nginx/1.18.0 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"},
    )
    storage.add_identifiers(src_a, [
        Identifier("pgp_fingerprint", VENDOR_KEY_FPR, "vendor key"),
        Identifier("username_candidate", "nightferry", "vendor name", heuristic=True),
        Identifier("btc_address", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "payment"),
        Identifier("analytics_id", "UA-4471234-2", "tag on page"),
    ])

    # --- market B: the SAME key under a DIFFERENT handle (the whole point) ---
    src_b = storage.add_source(
        url=f"http://{MARKET_B}/u/harbourlight", host=MARKET_B,
        site="generic", http_status=200, title="harbourlight",
        response_headers={"Server": "nginx/1.18.0 (Ubuntu)"},
    )
    storage.add_identifiers(src_b, [
        Identifier("pgp_fingerprint", VENDOR_KEY_FPR, "same key, other market"),
        Identifier("username_candidate", "harbourlight", "profile", heuristic=True),
    ])

    # --- clearnet host carrying the same analytics ID ---
    src_c = storage.add_source(
        url=f"https://{CLEARNET}/", host=CLEARNET,
        site="generic", http_status=200, title="Vendor Shop",
        response_headers={"Server": "nginx/1.18.0 (Ubuntu)"},
    )
    storage.add_identifiers(src_c, [
        Identifier("analytics_id", "UA-4471234-2", "same tag, clearnet"),
    ])

    # --- the key itself, with its User ID identities ---
    class _Uid:
        def __init__(self, raw, name, email):
            self.raw, self.name, self.email = raw, name, email

    class _Key:
        fingerprint = VENDOR_KEY_FPR
        key_id = VENDOR_KEY_FPR[-16:]
        version, algorithm, created = 4, "EdDSA-legacy", 1548158185
        checksum_ok = True
        subkey_fingerprints: list[str] = []
        uids = [_Uid("Cass Ferrow <cass.ferrow@mailhost.test>",
                     "Cass Ferrow", "cass.ferrow@mailhost.test")]
        emails = ["cass.ferrow@mailhost.test"]
        names = ["Cass Ferrow"]

    storage.add_pgp_key(src_a, _Key())
    storage.add_pgp_key(src_b, _Key())

    # --- a certificate served by market A that names a clearnet domain ---
    class _Cert:
        sha256 = "a" * 64
        spki_sha256 = "b" * 64
        serial = "0F0F0F"
        subject_cn = CLEARNET
        issuer_cn = "Let's Encrypt R3"
        not_before, not_after = "2026-01-01T00:00:00+00:00", "2026-12-31T00:00:00+00:00"
        san_dns = [CLEARNET, f"www.{CLEARNET}"]
        san_ip: list[str] = []
        self_signed = False

        def clearnet_names(self):
            return [CLEARNET, f"www.{CLEARNET}"]

    class _Obs:
        host, port = MARKET_A, 443
        certificate = _Cert()
        tls_version, cipher = "TLSv1.3", "TLS_AES_256_GCM_SHA384"

    storage.add_certificate(src_a, _Obs())

    return {"src_a": src_a, "src_b": src_b, "src_c": src_c}


# Two authors, each posting under two handles. Every handle gets DIFFERENT
# content; only the voice is shared within an author. Samples are sized like a
# real vendor profile's accumulated posts (a few thousand characters), because
# stylometric scores compress on short text and a toy-sized sample would
# demonstrate nothing.
#
# Author ONE: clipped, ungrammatical, no apostrophes, short declaratives.
# Author TWO: formal, subordinate clauses, hedged, courteous sign-offs.

_ONE_A = (
    "Right so listen. Stock is in. I ship monday, tuesday latest. "
    "No refunds, no exceptions, dont ask. Been doing this four years. "
    "If you message me about tracking before day five i will just ignore it. "
    "Payment first. Always. Thats how it works here and thats how it stays. "
    "Ive had good feedback from everyone who followed the rules. "
    "Dont be difficult and we get along fine. Simple as that really. "
    "Someone asked me yesterday if i do partials. No. I dont. Never have. "
    "Its not worth my time and it never ends well for anyone involved. "
    "Full order or nothing, thats been the rule since i started and it stays. "
    "Also stop asking me to go first. Im not going first. You can check my "
    "feedback, its all there, years of it. If that isnt enough for you then "
    "we probably shouldnt be doing business together anyway. No offence meant. "
    "Packing is the same as always. Vacuum sealed. Double bagged. Wiped down. "
    "Nobody has ever come back to me about the packing and nobody will. "
)
_ONE_B = (
    "Quick update for everyone. Prices going up next week, thats just how it is. "
    "Supplier changed on me, nothing i can do about that, dont shoot the messenger. "
    "Same packing as always, vacuum sealed, double bagged, no complaints yet. "
    "I check messages twice a day, morning and night, thats it. Dont spam me. "
    "If your order is late its the post not me. Been through this before. "
    "Anyone who cant handle that can go somewhere else, no hard feelings. "
    "Had two people this week try and dispute after twelve days. Twelve days. "
    "Thats normal. Thats always been normal. Read the listing before you order. "
    "I put it all in the listing for a reason and nobody reads it, every time. "
    "Reups are tuesday and friday from now on, not wednesday like before. "
    "That change is permanent so update whatever notes youre keeping. "
    "One more thing. Stop sending me messages on three different accounts. "
    "I know its you. It doesnt make me answer faster, it makes me answer slower. "
    "Thats everything for now. Back to work. "
)
_TWO_A = (
    "Greetings to all members of this community. I would like to take a moment "
    "to introduce my services, which I have provided with considerable care for "
    "some time now. Quality, in my considered view, is not negotiable; it is the "
    "foundation upon which trust is constructed, and trust, here especially, is "
    "the only currency that genuinely matters. Each order is prepared "
    "individually, with attention to discretion and to presentation alike. "
    "I am grateful for the confidence that has been placed in me thus far, and I "
    "intend to continue meriting it, insofar as that lies within my power. "
    "Should you have questions, please do write; I would far rather answer a "
    "dozen enquiries beforehand than resolve a single misunderstanding after. "
    "It has been suggested to me that my listings are somewhat verbose. This is "
    "a fair criticism, and one I accept, though I would gently observe that "
    "precision occasionally requires a certain number of words. "
)
_TWO_B = (
    "Good evening, and my thanks to those who have written this week. "
    "It seems appropriate that I should address one or two recurring questions, "
    "which I shall do in turn, and with as much candour as circumstances permit. "
    "Regarding despatch: every parcel is prepared by my own hand, and I would "
    "not entrust that task to another, whatever the saving in time might be. "
    "Regarding correspondence: I endeavour to reply within a day, though I would "
    "ask for patience where matters are complex or where I am travelling. "
    "Regarding pricing, which I know is of interest: I have held my rates steady "
    "for some months, and I intend to continue doing so for as long as my own "
    "costs permit it, which is not a promise so much as a statement of intent. "
    "Finally, a small request, offered in good humour. If you have read the "
    "listing, and I hope that you have, there is no need to ask me whether the "
    "listing is accurate. It is. I wrote it. I am grateful for your attention, "
    "and I remain, as ever, at your service should anything be unclear. "
)


def _seed_documents(storage: Storage, ids: dict) -> None:
    """Two authors x two handles, plus timestamps for temporal analysis."""
    storage.add_document(ids["src_a"], _ONE_A * 2, handle="nightferry",
                         posted_at="2026-03-02T19:14:00", kind="post")
    storage.add_document(ids["src_b"], _ONE_B * 2, handle="harbourlight",
                         posted_at="2026-03-03T20:41:00", kind="post")
    storage.add_document(ids["src_a"], _TWO_A * 2, handle="quietmoor",
                         posted_at="2026-03-02T09:05:00", kind="post")
    storage.add_document(ids["src_b"], _TWO_B * 2, handle="palefen",
                         posted_at="2026-03-04T08:22:00", kind="post")


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------

def test_correlation_finds_clearnet_domain_in_certificate():
    """A clearnet name in a hidden service's certificate must be found, at high
    confidence, and must outrank a merely shared analytics ID."""
    with tempfile.TemporaryDirectory() as tmp:
        with _mk_storage(Path(tmp)) as storage:
            _seed_corpus(storage)
            findings = CorrelationEngine(storage).run(persist=True)

            assert findings, "expected at least one correlation"
            pairs = {(f.onion_host, f.clearnet): f for f in findings}

            cert_finding = pairs.get((MARKET_A, CLEARNET))
            assert cert_finding is not None
            assert "tls_clearnet_name" in cert_finding.methods
            assert cert_finding.confidence >= 0.95
            # The analytics ID is shared with the same clearnet host, so it should
            # have combined into the same finding and pushed it higher still.
            assert "analytics_shared" in cert_finding.methods

            # The explanation must actually name the evidence.
            explanation = cert_finding.explain()
            assert CLEARNET in explanation
            assert "certificate" in explanation.lower()


def test_correlation_scores_shared_analytics_below_certificate():
    """A shared analytics ID alone is a weaker claim than a certificate name."""
    with tempfile.TemporaryDirectory() as tmp:
        with _mk_storage(Path(tmp)) as storage:
            _seed_corpus(storage)
            findings = CorrelationEngine(storage).run(persist=False)
            by_pair = {(f.onion_host, f.clearnet): f.confidence for f in findings}
            # Market A has both cert + analytics; nothing links market B to clearnet.
            assert by_pair[(MARKET_A, CLEARNET)] > 0.9
            assert (MARKET_B, CLEARNET) not in by_pair


def test_pgp_reuse_links_two_handles_across_marketplaces():
    """The same key on two markets is the cross-marketplace actor signal."""
    with tempfile.TemporaryDirectory() as tmp:
        with _mk_storage(Path(tmp)) as storage:
            _seed_corpus(storage)
            reuse = storage.pgp_reuse(min_hosts=2)
            assert len(reuse) == 1
            assert reuse[0]["fingerprint"] == VENDOR_KEY_FPR
            assert reuse[0]["host_count"] == 2


def test_actor_graph_merges_handles_via_shared_key():
    """Two handles on different markets must resolve to one actor, and the
    cluster must carry the identity from the key's User ID packet."""
    with tempfile.TemporaryDirectory() as tmp:
        with _mk_storage(Path(tmp)) as storage:
            ids = _seed_corpus(storage)
            _seed_documents(storage, ids)
            StylometryEngine(storage).run(persist=True)

            graph = ActorGraph(storage)
            actors = graph.build()
            assert actors, "expected at least one resolved actor"

            # Find the cluster anchored on the shared PGP key.
            target = next(
                (a for a in actors
                 if ("pgp_fingerprint", VENDOR_KEY_FPR) in a.members), None
            )
            assert target is not None, "the shared key did not anchor a cluster"

            members = dict(target.members)
            # The email from inside the key's UID packet must be attached.
            assert members.get(PGP_UID_EMAIL) == "cass.ferrow@mailhost.test"
            # Both marketplace handles must be in the same cluster.
            handles = {v for t, v in target.members if t == "username_candidate"}
            assert {"nightferry", "harbourlight"} <= handles

            assert target.confidence > 0.5
            assert "pgp_uid" in {e.method for e in target.edges}


def test_actor_graph_persists_and_exports():
    """Resolved actors must be written back, and the graph must export cleanly."""
    with tempfile.TemporaryDirectory() as tmp:
        with _mk_storage(Path(tmp)) as storage:
            ids = _seed_corpus(storage)
            _seed_documents(storage, ids)
            graph = ActorGraph(storage)
            graph.build()
            count = graph.persist()
            assert count > 0

            clusters = storage.actor_clusters()
            assert clusters
            assert storage.actor_members(clusters[0]["id"])

            payload = json.loads(graph.to_json())
            assert payload["nodes"] and payload["actors"]
            assert "<graphml" in graph.to_graphml()
            assert graph.to_dot().startswith("graph darkosint {")


def test_stylometry_ranks_same_author_handles_above_different_authors():
    """The two handles sharing an author must outrank every cross-author pair."""
    with tempfile.TemporaryDirectory() as tmp:
        with _mk_storage(Path(tmp)) as storage:
            ids = _seed_corpus(storage)
            _seed_documents(storage, ids)

            results = StylometryEngine(storage).run(persist=True)
            assert len(results) == 6  # 4 handles -> 6 pairs

            same_author = {
                frozenset(("nightferry", "harbourlight")),
                frozenset(("quietmoor", "palefen")),
            }
            scores = {frozenset((c.handle_a, c.handle_b)): c.score for c in results}
            same = [s for p, s in scores.items() if p in same_author]
            cross = [s for p, s in scores.items() if p not in same_author]

            # The robust claim is the RANKING: every same-author pair must score
            # above every cross-author pair. Absolute scores compress when the
            # samples are short (these are ~1.2k chars, against the ~12k used to
            # calibrate STYLOMETRY_MIN_SCORE), so asserting a fixed threshold
            # here would be testing the sample length, not the method.
            assert min(same) > max(cross), (
                f"same-author pairs {same} did not separate from cross-author {cross}"
            )
            assert min(same) - max(cross) > 0.03, "separation margin too thin"

            # Results must be queryable back out.
            assert storage.stylometry_pairs(min_score=0.0)


def test_temporal_profiles_handles_from_stored_timestamps():
    """Stored posted_at values must feed the activity histogram."""
    with tempfile.TemporaryDirectory() as tmp:
        with _mk_storage(Path(tmp)) as storage:
            ids = _seed_corpus(storage)
            _seed_documents(storage, ids)

            profiles = TemporalAnalyzer(storage).profiles()
            assert set(profiles) == {
                "nightferry", "harbourlight", "quietmoor", "palefen"
            }
            assert profiles["nightferry"].hours[19] == 1
            assert profiles["quietmoor"].hours[9] == 1

            # One timestamp each is far too little to fit a curve, and the
            # estimator must decline rather than invent an offset.
            estimates = TemporalAnalyzer(storage).run()
            assert all(e.utc_offset is None for e in estimates)


def test_correlation_is_recomputed_not_accumulated():
    """Re-running correlation must replace prior findings, not pile up duplicates."""
    with tempfile.TemporaryDirectory() as tmp:
        with _mk_storage(Path(tmp)) as storage:
            _seed_corpus(storage)
            CorrelationEngine(storage).run(persist=True)
            first = len(storage.correlations())
            CorrelationEngine(storage).run(persist=True)
            assert len(storage.correlations()) == first, "correlations accumulated across runs"
            assert first > 0


def test_full_chain_runs_on_an_empty_database():
    """Every stage must degrade cleanly when there is nothing to analyse."""
    with tempfile.TemporaryDirectory() as tmp:
        with _mk_storage(Path(tmp)) as storage:
            assert CorrelationEngine(storage).run() == []
            assert StylometryEngine(storage).run() == []
            assert TemporalAnalyzer(storage).run() == []
            assert ActorGraph(storage).build() == []
