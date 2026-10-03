#!/usr/bin/env python3
"""Offline demonstration of the analysis pipeline.

Builds a synthetic corpus with **known ground truth** — two marketplaces and a
clearnet site, one operator publishing the same PGP key under two different
handles, a TLS certificate leaking a clearnet domain, a shared analytics ID, and
two authors writing under two handles each — then runs the full analysis chain
over it.

It also plants **decoys**: a market index page listing many unrelated vendors'
keys, and two separate vendors that share only a market's footer contact. A
naive resolver fuses those into phantom actors; this one must not. The scorecard
at the end checks both the planted links (were they recovered?) and the decoys
(were they kept apart?), so the demo proves precision, not just recall.

This exists because the interesting behaviour of this toolkit is the *analysis*,
and demonstrating that should not require crawling a live illicit marketplace.
Everything here is offline: no Tor, no network, no real site, no real person.

    python demo.py                 # seed ./demo_data and run the analysis
    python demo.py --output foo/   # somewhere else
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from darkosint.extractors import Identifier                 # noqa: E402
from darkosint.logging_setup import setup_logging          # noqa: E402
from darkosint.storage import Storage                       # noqa: E402
from tests.test_integration import (                        # noqa: E402
    MARKET_A, CLEARNET, VENDOR_KEY_FPR, _seed_corpus, _seed_documents,
)

import scraper  # noqa: E402

# A third market used only for decoys — traps a naive resolver should fail.
MARKET_C = "ccccbazaarccccbazaarccccbazaarccccbazaarccccbazaarcccc.onion"
FOOTER_EMAIL = "support@ccccbazaar.example"


def _seed_decoys(storage: Storage) -> dict:
    """Plant false-merge traps, and return the ground truth about them.

    Trap 1 — a vendor *directory* page listing six unrelated vendors' PGP keys.
             A resolver that links co-published identifiers naively fuses all six.
    Trap 2 — two separate vendors on the same market, each with their own key and
             wallet, sharing only the market's footer support address. The shared
             footer must not bridge them into one actor.
    """
    directory_keys = [f"{c * 40}" for c in "1234ABCDEF"[:6]]
    dir_src = storage.add_source(
        url=f"http://{MARKET_C}/vendors", host=MARKET_C,
        site="generic", http_status=200, title="Vendor directory",
        response_headers={"Server": "nginx"},  # stock banner: attributes nothing
    )
    storage.add_identifiers(
        dir_src,
        [Identifier("pgp_fingerprint", k, "listed in vendor index") for k in directory_keys],
    )

    footer_keys = ["7" * 40, "8" * 40]
    for i, key in enumerate(footer_keys):
        src = storage.add_source(
            url=f"http://{MARKET_C}/vendor/{i}", host=MARKET_C,
            site="generic", http_status=200, title=f"vendor {i}",
            response_headers={"Server": "nginx"},
        )
        storage.add_identifiers(src, [
            Identifier("pgp_fingerprint", key, "vendor's own key"),
            Identifier("btc_address", f"1DecoyVendor{i}WalletWalletWaX"),
            Identifier("email", FOOTER_EMAIL, "site footer contact"),
        ])

    return {"directory_keys": directory_keys, "footer_keys": footer_keys}


def _scorecard(db: Path, truth: dict) -> bool:
    """Grade the run against ground truth. Returns True if every check passed."""
    checks: list[tuple[str, bool, str]] = []
    with Storage(db) as storage:
        clusters = storage.actor_clusters()
        members = {c["id"]: storage.actor_members(c["id"]) for c in clusters}

        def pgp_of(cid):
            return {m["identifier_value"] for m in members[cid]
                    if m["identifier_type"] == "pgp_fingerprint"}

        def handles_of(cid):
            return {m["identifier_value"] for m in members[cid]
                    if m["identifier_type"] == "username_candidate"}

        # RECALL: the two same-key handles must land in one actor.
        shared_key_cluster = next(
            (c for c in clusters if VENDOR_KEY_FPR in pgp_of(c["id"])), None
        )
        merged = (
            shared_key_cluster is not None
            and {"nightferry", "harbourlight"} <= handles_of(shared_key_cluster["id"])
        )
        checks.append((
            "shared PGP key merges 'nightferry' + 'harbourlight' into one actor",
            merged,
            "found" if merged else "MISSED the cross-market link",
        ))

        # RECALL: the second author's two handles link on style alone.
        style_cluster = next(
            (c for c in clusters
             if handles_of(c["id"]) >= {"quietmoor", "palefen"}
             and not pgp_of(c["id"])),
            None,
        )
        checks.append((
            "stylometry links 'quietmoor' + 'palefen' (style only, no shared key)",
            style_cluster is not None,
            "found" if style_cluster else "MISSED the style-only link",
        ))

        # PRECISION: no decoy directory keys may share an actor.
        decoy_keys = set(truth["directory_keys"]) | set(truth["footer_keys"])
        worst = max((len(pgp_of(c["id"]) & decoy_keys) for c in clusters), default=0)
        no_false_merge = worst <= 1
        checks.append((
            "decoy directory + shared-footer keys are NOT fused (0 false merges)",
            no_false_merge,
            "kept apart" if no_false_merge
            else f"FALSE MERGE: one actor holds {worst} unrelated decoy keys",
        ))

        # CORRELATION: the certificate's clearnet name must score high.
        corr = {(c["onion_host"], c["clearnet"]): c["confidence"]
                for c in storage.correlations()}
        cert_conf = corr.get((MARKET_A, CLEARNET), 0.0)
        checks.append((
            f"onion→clearnet correlation for {CLEARNET} scores ≥ 0.90",
            cert_conf >= 0.90,
            f"confidence {cert_conf:.2f}",
        ))

    print("\n" + "=" * 72)
    print(" SCORECARD  (ground truth vs. what the chain recovered)")
    print("=" * 72)
    passed = 0
    for label, ok, detail in checks:
        mark = "PASS" if ok else "FAIL"
        passed += ok
        print(f"  [{mark}] {label}\n         → {detail}")
    print("-" * 72)
    print(f"  {passed}/{len(checks)} checks passed.")
    print("=" * 72)
    return passed == len(checks)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", default="demo_data", help="Where to build the demo DB.")
    ap.add_argument("--keep", action="store_true", help="Reuse an existing demo DB.")
    args = ap.parse_args()

    out = Path(args.output)
    if out.exists() and not args.keep:
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    setup_logging(out, verbose=False)

    db = out / "osint.db"
    truth: dict = {}
    if not db.exists() or not args.keep:
        with Storage(db) as storage:
            ids = _seed_corpus(storage)
            _seed_documents(storage, ids)
            truth = _seed_decoys(storage)

    print(__doc__.split("\n\n")[1].strip())
    print("\nGround truth planted in this corpus:")
    print("  * 'nightferry' (market A) and 'harbourlight' (market B) are ONE actor,")
    print("    linked by a shared PGP key whose User ID names Cass Ferrow.")
    print("  * Market A's TLS certificate names the clearnet domain, and the same")
    print("    analytics ID appears on both market A and that clearnet host.")
    print("  * 'quietmoor' and 'palefen' are a SECOND author, sharing only a style.")
    print("  * DECOYS: market C lists 6 unrelated vendors' keys on one index page,")
    print("    and two market-C vendors share only a footer email — none of these")
    print("    may be fused into a single actor.")
    print("\nThe analysis below was given none of that — only the raw artifacts.")

    argv = [
        "--output", str(out),
        "--analyse",
        "--export", str(out / "actor_graph.json"),
    ]
    rc = scraper.main(argv)
    if rc != 0:
        return rc

    ok = _scorecard(db, truth)
    print(
        "\nEvery scored finding above ships with its evidence (`explain()`); the "
        "scorecard grades this run's precision and recall against the planted "
        "ground truth. Leads, not verdicts."
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
