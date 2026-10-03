"""Unit tests for the analysis layer: correlation scoring, graph resolution,
stylometry measures, and temporal inference.

All offline and deterministic.
"""
from __future__ import annotations

import math

from darkosint.correlation import METHOD_WEIGHTS, combine, is_onion
from darkosint.graph import (
    STRONG_THRESHOLD,
    TYPE_STRENGTH,
    Actor,
    Edge,
    _UnionFind,
)
from darkosint.stylometry import (
    build_corpus_model,
    build_profile,
    cosine_delta,
    standardize,
)
from darkosint.temporal import (
    REFERENCE_CURVE,
    TimeProfile,
    extract_timestamps,
    infer_timezone,
    quiet_window,
)

# ---------------------------------------------------------------------------
# correlation scoring
# ---------------------------------------------------------------------------


def test_is_onion():
    assert is_onion("abc.onion") and is_onion("ABC.ONION")
    assert not is_onion("example.test") and not is_onion("")


def test_noisy_or_combination_reinforces_without_reaching_certainty():
    assert combine([]) == 0.0
    assert combine([0.5]) == 0.5
    # Two independent weak signals should beat either alone...
    assert combine([0.5, 0.5]) == 0.75
    # ...but nothing short of certainty should produce certainty.
    assert combine([0.9, 0.9, 0.9]) < 1.0
    assert combine([0.95, 0.85]) > 0.95


def test_a_certificate_name_outweighs_every_soft_signal():
    """A clearnet name in the hidden service's own cert must dominate."""
    cert = METHOD_WEIGHTS["tls_clearnet_name"]
    soft = [
        METHOD_WEIGHTS["banner_shared"],
        METHOD_WEIGHTS["cookie_shared"],
        METHOD_WEIGHTS["clearnet_reference"],
    ]
    assert cert > combine(soft)


def test_verified_match_is_the_highest_tier():
    assert METHOD_WEIGHTS["verified_spki_match"] >= max(
        w for k, w in METHOD_WEIGHTS.items() if not k.startswith("verified_")
    )


def test_default_certificate_names_are_not_clearnet_leaks():
    """A stock self-signed name identifies nobody and must not be a lead."""
    from darkosint.correlation import _is_default_cert_name

    for junk in ("localhost", "localhost.localdomain", "server.local",
                 "example.com", "UBUNTU", "changeme"):
        assert _is_default_cert_name(junk), junk
    for real in ("shop.example-vendor.test", "market.io", "acme-drops.biz"):
        assert not _is_default_cert_name(real), real


# ---------------------------------------------------------------------------
# graph primitives
# ---------------------------------------------------------------------------

def test_union_find_merges_transitively():
    uf = _UnionFind()
    uf.union(("a", "1"), ("b", "2"))
    uf.union(("b", "2"), ("c", "3"))
    assert uf.find(("a", "1")) == uf.find(("c", "3"))
    assert uf.find(("a", "1")) != uf.find(("d", "4"))


def test_type_strength_ordering_reflects_identifier_uniqueness():
    """A cryptographic identity must outrank a handle by a wide margin."""
    assert TYPE_STRENGTH["pgp_fingerprint"] == 1.0
    assert TYPE_STRENGTH["pgp_fingerprint"] > TYPE_STRENGTH["email"]
    assert TYPE_STRENGTH["email"] > TYPE_STRENGTH["username_candidate"]
    assert TYPE_STRENGTH["username_candidate"] > TYPE_STRENGTH["onion_url"]
    # Handles collide between people, so they must not count as strong anchors.
    assert TYPE_STRENGTH["username_candidate"] < STRONG_THRESHOLD


def test_actor_label_prefers_the_most_identifying_member():
    actor = Actor(id=1, members=[
        ("username_candidate", "somehandle"),
        ("pgp_fingerprint", "A" * 40),
    ])
    assert actor.choose_label() == "PGP:" + "A" * 16

    handles_only = Actor(id=2, members=[("username_candidate", "bob")])
    assert handles_only.choose_label() == "@bob"


def test_cluster_without_a_strong_anchor_is_penalised():
    """Handles joined only by style must score below a key-anchored cluster."""
    weak = Actor(id=1, members=[
        ("username_candidate", "a"), ("username_candidate", "b"),
    ])
    weak.edges = [Edge(("username_candidate", "a"), ("username_candidate", "b"),
                       0.70, "stylometry", {})]

    strong = Actor(id=2, members=[
        ("pgp_fingerprint", "F" * 40), ("username_candidate", "a"),
    ])
    strong.edges = [Edge(("pgp_fingerprint", "F" * 40), ("username_candidate", "a"),
                         0.70, "co_occurrence", {})]

    from darkosint.graph import ActorGraph

    graph = ActorGraph.__new__(ActorGraph)
    assert graph._score(weak) < graph._score(strong)


def test_actor_explanation_marks_weak_members():
    actor = Actor(id=1, members=[
        ("pgp_fingerprint", "A" * 40), ("username_candidate", "handle"),
    ])
    actor.edges = [Edge(("pgp_fingerprint", "A" * 40),
                        ("username_candidate", "handle"), 0.5, "co_occurrence", {})]
    actor.label = actor.choose_label()
    text = actor.explain()
    assert "[weak]" in text
    assert "co_occurrence" in text


# ---------------------------------------------------------------------------
# stylometry measures
# ---------------------------------------------------------------------------

def test_cosine_delta_is_rescaled_to_unit_interval():
    a = {"x": 1.0, "y": 0.0}
    assert cosine_delta(a, a) == 1.0                      # identical
    assert cosine_delta(a, {"x": -1.0, "y": 0.0}) == 0.0  # opposite
    assert cosine_delta(a, {"x": 0.0, "y": 1.0}) == 0.5   # orthogonal


def test_standardization_drops_dimensions_the_corpus_shares():
    """A feature identical across every author discriminates nothing."""
    texts = ["the same words here " * 40] * 3
    profiles = [build_profile(f"h{i}", [t]) for i, t in enumerate(texts)]
    model = build_corpus_model(profiles)
    # Every profile is identical, so every dimension has zero variance.
    assert standardize(profiles[0], model) == {}


def test_profiles_below_the_minimum_are_not_usable():
    assert not build_profile("h", ["too short"]).usable
    assert build_profile("h", ["word " * 200]).usable


def test_structural_features_are_length_invariant():
    """Doubling the text must not change the typographic signature.

    Guards a real trap: type/token ratio and hapax rate fall as text grows, so
    computed over the whole sample they encode how much text was collected
    rather than who wrote it — and would then match authors by corpus size.
    They are computed over a fixed token window for exactly this reason.
    """
    text = "Hello there! How are you? I am fine, thanks. "
    one = build_profile("a", [text * 4]).structural
    two = build_profile("b", [text * 8]).structural
    for key in one:
        assert math.isclose(one[key], two[key], rel_tol=0.05), (
            f"{key} varies with sample length: {one[key]} vs {two[key]}"
        )


# ---------------------------------------------------------------------------
# temporal
# ---------------------------------------------------------------------------

def test_extract_timestamps_handles_common_forum_formats():
    from datetime import datetime

    text = (
        "Posted 2024-03-11 14:32:09 | edited 11/03/2024 16:05 | "
        "5 Mar 2024 at 09:15 | March 7, 2024 at 22:41 | 3 hours ago"
    )
    stamps = extract_timestamps(text, reference=datetime(2024, 3, 11, 18, 0))
    hours = sorted(s.hour for s in stamps)
    assert hours == [9, 14, 15, 16, 22]


def test_relative_timestamps_need_an_anchor():
    assert extract_timestamps("posted 3 hours ago") == []


def test_quiet_window_finds_the_least_active_hours():
    histogram = [0.0] * 24
    for hour in range(8, 23):
        histogram[hour] = 1.0 / 15
    start, _ = quiet_window(histogram, width=6)
    assert start in (23, 0, 1, 2)


def test_timezone_inference_recovers_a_known_offset():
    """A synthetic actor on a normal diurnal schedule must be located."""
    import random

    random.seed(11)
    for true_offset in (0, 5, -8, 9):
        profile = TimeProfile(subject="x")
        for _ in range(400):
            local = random.choices(range(24), weights=REFERENCE_CURVE)[0]
            profile.hours[(local - true_offset) % 24] += 1
        estimate = infer_timezone(profile)
        assert estimate.utc_offset == true_offset, (
            f"expected UTC{true_offset:+d}, got UTC{estimate.utc_offset:+d}"
        )
        assert estimate.confidence > 0.4


def test_flat_activity_yields_no_confident_offset():
    """Round-the-clock posting (a bot, or a shared account) must not be located."""
    profile = TimeProfile(subject="bot")
    for hour in range(24):
        profile.hours[hour] = 50
    estimate = infer_timezone(profile)
    assert estimate.confidence < 0.3


def test_too_few_samples_declines_to_guess():
    profile = TimeProfile(subject="x")
    profile.hours[3] = 2
    estimate = infer_timezone(profile, min_samples=8)
    assert estimate.utc_offset is None
    assert estimate.confidence == 0.0
    assert "insufficient data" in estimate.explain()
