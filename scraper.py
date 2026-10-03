#!/usr/bin/env python3
"""Dark web OSINT collector — single CLI entrypoint.

Passive collection only. Routes all traffic through Tor, crawls seed .onion
URLs, snapshots pages for evidentiary reproducibility, extracts structured
identifiers, and stores everything in a local SQLite database.

Examples
--------
Crawl:
    python scraper.py --seeds seeds.txt --output data/
    python scraper.py --seeds seeds.txt --output data/ --max-pages 20 --rotate-every 10

Verify Tor is working before a run:
    python scraper.py --check-tor

Query results back out:
    python scraper.py --output data/ --query --handle shadowvendor
    python scraper.py --output data/ --query --value bc1qxy... --exact
    python scraper.py --output data/ --query --type btc_address
    python scraper.py --output data/ --query --pivot someuser
    python scraper.py --output data/ --query --shared 2
    python scraper.py --output data/ --query --list-sources
    python scraper.py --output data/ --query --stats

Analyse what was collected (all offline unless noted):
    python scraper.py --output data/ --correlate            # onion -> clearnet
    python scraper.py --output data/ --correlate --verify   # + live clearnet check
    python scraper.py --output data/ --graph                # resolve actors
    python scraper.py --output data/ --graph --export graph.json
    python scraper.py --output data/ --stylometry           # authorship attribution
    python scraper.py --output data/ --temporal             # timezone inference
    python scraper.py --output data/ --llm-enrich           # AI claim extraction
    python scraper.py --output data/ --analyse              # run the whole chain
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from darkosint import __version__
from darkosint.config import Config, load_seeds
from darkosint.logging_setup import setup_logging
from darkosint.storage import Storage

DEFAULT_DB_NAME = "osint.db"


# ---------------------------------------------------------------------------
# argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scraper.py",
        description="Passive dark web OSINT collector (Tor-routed).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--version", action="version", version=f"darkosint {__version__}")
    p.add_argument("--config", metavar="FILE", help="Path to config.ini (optional).")
    p.add_argument(
        "--output",
        "-o",
        default="data",
        metavar="DIR",
        help="Output directory for the DB, snapshots, and audit log (default: data/).",
    )
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose console logs.")

    # Modes
    p.add_argument("--seeds", metavar="FILE", help="Seed .onion URL list (crawl mode).")
    p.add_argument(
        "--check-tor",
        action="store_true",
        help="Verify traffic exits through Tor, then exit.",
    )
    p.add_argument("--query", action="store_true", help="Query stored results, then exit.")

    # Crawl overrides
    g = p.add_argument_group("crawl overrides")
    g.add_argument("--max-pages", type=int, help="Cap pages fetched this run.")
    g.add_argument("--max-depth", type=int, help="Link-hops from seeds to follow.")
    g.add_argument("--rotate-every", type=int, help="New Tor circuit every N requests.")
    g.add_argument("--per-host-delay", type=float, help="Min seconds between same-host hits.")
    g.add_argument(
        "--probe-tls", action="store_true",
        help="Also open port 443 on http-only hosts to capture a certificate "
             "(an extra connection; off by default).",
    )
    g.add_argument(
        "--favicon", action="store_true",
        help="Fetch each host's favicon to compute its Shodan-compatible hash "
             "(one extra GET per host; off by default).",
    )
    g.add_argument(
        "--no-tls", action="store_true",
        help="Do not capture TLS certificates even on https:// pages.",
    )
    g.add_argument(
        "--no-expand",
        action="store_true",
        help="Do not follow discovered onion links (seeds only).",
    )
    g.add_argument(
        "--stay-on-seed-hosts",
        action="store_true",
        help="Only follow links that stay on a seed host.",
    )
    g.add_argument(
        "--watch", type=float, metavar="SECS",
        help="Live monitoring: re-crawl the seeds every SECS seconds (min 30, to "
             "stay polite) and report what changed each pass. Ctrl-C to stop.",
    )

    # Query selectors
    q = p.add_argument_group("query selectors (use with --query)")
    q.add_argument("--handle", metavar="X", help="Find username candidates matching X.")
    q.add_argument("--value", metavar="X", help="Find any identifier matching value X.")
    q.add_argument("--exact", action="store_true", help="Make --value an exact match.")
    q.add_argument("--type", metavar="T", dest="qtype", help="List identifiers of type T.")
    q.add_argument("--pivot", metavar="X", help="Show all sources containing value X.")
    q.add_argument(
        "--shared",
        type=int,
        metavar="N",
        help="List identifiers seen across >= N distinct sources.",
    )
    q.add_argument("--list-sources", action="store_true", help="List crawled sources.")
    q.add_argument("--stats", action="store_true", help="Show identifier counts by type.")
    q.add_argument("--certs", action="store_true", help="List captured TLS certificates.")
    q.add_argument("--keys", action="store_true", help="List parsed PGP keys and their UIDs.")

    # analysis modes
    a = p.add_argument_group("analysis (offline unless stated)")
    a.add_argument(
        "--analyse", "--analyze", dest="analyse", action="store_true",
        help="Run the full analysis chain: correlate, stylometry, temporal, graph.",
    )
    a.add_argument(
        "--correlate", action="store_true",
        help="Score onion -> clearnet infrastructure correlations.",
    )
    a.add_argument(
        "--verify", action="store_true",
        help="With --correlate: connect to candidate clearnet hosts THROUGH TOR "
             "and compare their certificates (network, but your IP is not exposed).",
    )
    a.add_argument(
        "--verify-direct", action="store_true",
        help="With --verify: connect from your REAL IP instead of over Tor "
             "(faster, but reveals your address to the candidate host).",
    )
    a.add_argument(
        "--ct-lookup", action="store_true",
        help="With --correlate: query Certificate Transparency logs (NETWORK).",
    )
    a.add_argument("--graph", action="store_true", help="Resolve identifiers into actors.")
    a.add_argument(
        "--edge-threshold", type=float, metavar="W",
        help="Minimum edge weight for the actor graph (default 0.35).",
    )
    a.add_argument(
        "--export", metavar="FILE",
        help="With --graph: write the graph to FILE (.json, .graphml, or .dot).",
    )
    a.add_argument(
        "--stylometry", action="store_true",
        help="Rank handle pairs by writing-style similarity.",
    )
    a.add_argument(
        "--temporal", action="store_true",
        help="Infer each handle's likely UTC offset from activity times.",
    )
    a.add_argument(
        "--llm-enrich", action="store_true",
        help="Extract self-disclosed claims with Claude (NETWORK, needs an API key).",
    )
    a.add_argument(
        "--llm-assess", action="store_true",
        help="With --graph/--correlate: have Claude review each finding (NETWORK).",
    )
    a.add_argument(
        "--llm-limit", type=int, default=20, metavar="N",
        help="Max documents/findings to send for AI analysis (default 20).",
    )
    a.add_argument(
        "--min-confidence", type=float, default=0.0, metavar="C",
        help="Hide findings below this confidence (default 0.0).",
    )
    return p


def resolve_config(args: argparse.Namespace) -> Config:
    cfg = Config.load(args.config)
    overrides = {
        "crawl.max_pages": args.max_pages,
        "crawl.max_depth": args.max_depth,
        "crawl.expand_frontier": False if args.no_expand else None,
        "crawl.stay_on_seed_hosts": True if args.stay_on_seed_hosts else None,
        "tor.rotate_every": args.rotate_every,
        "http.per_host_delay": args.per_host_delay,
        "evidence.probe_tls_on_http": True if args.probe_tls else None,
        "evidence.fetch_favicon": True if args.favicon else None,
        "evidence.capture_tls": False if args.no_tls else None,
    }
    return cfg.with_overrides(**overrides)


# ---------------------------------------------------------------------------
# modes
# ---------------------------------------------------------------------------

def mode_check_tor(cfg: Config) -> int:
    from darkosint.tor_session import TorSession, TorUnavailableError

    try:
        with TorSession(cfg) as session:
            res = session.check_connectivity()
    except TorUnavailableError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    if res.ok and "Congratulations" in res.text:
        print("[+] Tor is working: traffic is exiting through the Tor network.")
        return 0
    if res.ok:
        print("[!] Reached the check endpoint but could not confirm Tor. Response:")
        print("    " + res.text.strip().replace("\n", " ")[:200])
        return 1
    print(f"[!] Could not reach Tor check endpoint: {res.error or res.status}")
    print("    Is `tor` running and listening on the configured SOCKS port?")
    return 2


def mode_crawl(cfg: Config, args: argparse.Namespace, output_dir: Path) -> int:
    from darkosint.crawler import Crawler
    from darkosint.tor_session import TorSession, TorUnavailableError

    seeds = load_seeds(args.seeds)
    if not seeds:
        print("[!] No seeds found in seeds file.", file=sys.stderr)
        return 1
    print(f"[*] Loaded {len(seeds)} seed(s). Output -> {output_dir}")

    db_path = output_dir / DEFAULT_DB_NAME
    try:
        session = TorSession(cfg)
    except TorUnavailableError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    with session, Storage(db_path) as storage:
        crawler = Crawler(cfg, session, storage, output_dir)
        stats = crawler.crawl(seeds)

    print_summary(stats)
    return 0


def mode_watch(cfg: Config, args: argparse.Namespace, output_dir: Path) -> int:
    """Continuously re-crawl the seeds, reporting the delta after each pass.

    This is the toolkit's live-monitoring loop: the same passive pipeline, run on
    a fixed, deliberately polite interval so a target is checked for new content
    without being hammered. Each pass prints how many pages and identifiers were
    added since the last one; the running dashboard shows the detail live.
    """
    import time
    from datetime import datetime
    from darkosint.crawler import Crawler
    from darkosint.tor_session import TorSession, TorUnavailableError

    seeds = load_seeds(args.seeds)
    if not seeds:
        print("[!] No seeds found in seeds file.", file=sys.stderr)
        return 1
    interval = max(30.0, args.watch)  # never poll a target faster than this
    db_path = output_dir / DEFAULT_DB_NAME
    print(f"[*] LIVE WATCH — {len(seeds)} seed(s), every {interval:g}s. Ctrl-C to stop.")
    print(f"[*] Writing to {db_path}.  Point the dashboard here to watch it fill.")

    pass_no = 0
    try:
        while True:
            pass_no += 1
            try:
                session = TorSession(cfg)
            except TorUnavailableError as exc:
                print(f"[!] {exc}", file=sys.stderr)
                return 2
            with session, Storage(db_path) as storage:
                before_pages = storage.source_count()
                before_ids = sum(storage.counts_by_type().values())
                Crawler(cfg, session, storage, output_dir).crawl(seeds)
                after_pages = storage.source_count()
                after_ids = sum(storage.counts_by_type().values())
            stamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{stamp}] pass {pass_no}: +{after_pages - before_pages} pages, "
                  f"+{after_ids - before_ids} identifiers "
                  f"(totals: {after_pages} pages, {after_ids} identifiers)")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Live watch stopped.")
        return 0


def print_summary(stats) -> None:
    print("\n" + "=" * 52)
    print(" CRAWL SUMMARY")
    print("=" * 52)
    print(f"  Pages fetched      : {stats.pages_fetched}")
    print(f"  Pages failed       : {stats.pages_failed}")
    print(f"  Onion links found  : {stats.links_discovered}")
    print(f"  Identifiers stored : {stats.identifiers_added}")
    print(f"  Exposures noted    : {stats.exposures_noted}  (detection only)")
    print(f"  TLS certs captured : {stats.certificates_captured}")
    if stats.clearnet_names_found:
        print(f"  ** CLEARNET NAMES IN CERTIFICATES: {stats.clearnet_names_found} **")
    print(f"  PGP keys parsed    : {stats.pgp_keys_parsed}")
    print(f"  Documents stored   : {stats.documents_stored}")
    print("  Identifiers by type:")
    if stats.identifiers_by_type:
        for type_, n in sorted(
            stats.identifiers_by_type.items(), key=lambda kv: (-kv[1], kv[0])
        ):
            print(f"      {type_:<20} {n}")
    else:
        print("      (none)")
    print("=" * 52)


def mode_query(args: argparse.Namespace, output_dir: Path) -> int:
    db_path = output_dir / DEFAULT_DB_NAME
    if not db_path.exists():
        print(f"[!] No database at {db_path}. Run a crawl first.", file=sys.stderr)
        return 1

    with Storage(db_path) as storage:
        if args.stats:
            counts = storage.counts_by_type()
            print(f"Sources crawled: {storage.source_count()}")
            print("Identifiers by type:")
            for type_, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
                print(f"  {type_:<20} {n}")
            return 0

        if args.list_sources:
            rows = storage.list_sources()
            for r in rows:
                print(
                    f"[{r['id']}] {r['http_status']} d{r['depth']} "
                    f"{r['site']:<14} {r['url']}"
                )
            print(f"\n{len(rows)} source(s).")
            return 0

        if args.handle:
            rows = storage.find_handles(args.handle)
            _print_rows(rows, f"username candidates matching '{args.handle}'")
            return 0

        if args.value:
            rows = storage.find_by_value(args.value, exact=args.exact)
            _print_rows(rows, f"identifiers matching value '{args.value}'")
            return 0

        if args.qtype:
            rows = storage.find_by_type(args.qtype)
            _print_rows(rows, f"identifiers of type '{args.qtype}'")
            return 0

        if args.pivot:
            rows = storage.pivot(args.pivot)
            print(f"Sources containing '{args.pivot}':")
            for r in rows:
                print(f"  [{r['source_id']}] {r['type']:<16} {r['url']} ({r['scan_date']})")
            print(f"\n{len(rows)} source(s).")
            return 0

        if args.certs:
            rows = storage.certificates()
            print(f"TLS certificates captured: {len(rows)}")
            for r in rows:
                san = ", ".join(json.loads(r["san_dns"] or "[]")) or "-"
                print(f"\n  {r['host']}:{r['port']}  ({r['tls_version']}, {r['cipher']})")
                print(f"    subject CN : {r['subject_cn'] or '-'}")
                print(f"    issuer  CN : {r['issuer_cn'] or '-'}"
                      f"{'   [SELF-SIGNED]' if r['self_signed'] else ''}")
                print(f"    SAN DNS    : {san}")
                print(f"    valid      : {r['not_before']} -> {r['not_after']}")
                print(f"    cert sha256: {r['sha256']}")
                print(f"    spki sha256: {r['spki_sha256']}")
            return 0

        if args.keys:
            rows = storage.pgp_keys()
            print(f"PGP keys parsed: {len(rows)}")
            for r in rows:
                uids = json.loads(r["uids"] or "[]")
                print(f"\n  {r['fingerprint']}")
                print(f"    key ID  : {r['key_id']}  (v{r['version']} {r['algorithm']})"
                      f"{'' if r['checksum_ok'] else '   [ARMOR CRC FAILED]'}")
                print(f"    seen on : {r['host'] or '?'}")
                for uid in uids:
                    print(f"    User ID : {uid}")
            reuse = storage.pgp_reuse(min_hosts=2)
            if reuse:
                print("\n  ** CROSS-HOST KEY REUSE (same actor on multiple sites) **")
                for r in reuse:
                    print(f"    {r['fingerprint']}  on {r['host_count']}: {r['hosts']}")
            return 0

        if args.shared is not None:
            rows = storage.shared_identifiers(min_sources=args.shared)
            print(f"Identifiers shared across >= {args.shared} sources:")
            for r in rows:
                print(
                    f"  {r['type']:<16} {r['value']:<48} "
                    f"in {r['source_count']} sources (ids: {r['source_ids']})"
                )
            print(f"\n{len(rows)} identifier(s).")
            return 0

    print("[!] --query needs a selector (--handle/--value/--type/--pivot/--shared/"
          "--list-sources/--stats/--certs/--keys).", file=sys.stderr)
    return 1


def _print_rows(rows, header: str) -> None:
    print(f"{header}:  ({len(rows)} hit(s))")
    for r in rows:
        keys = r.keys()
        type_ = r["type"] if "type" in keys else "identifier"
        heur = " [heuristic]" if ("heuristic" in keys and r["heuristic"]) else ""
        value = r["value"]
        print(f"  {type_:<16} {value}{heur}")
        print(f"      source: {r['url']}  ({r['scan_date']})")
        if "context" in keys and r["context"]:
            print(f"      context: …{r['context']}…")


# ---------------------------------------------------------------------------
# analysis modes
# ---------------------------------------------------------------------------

def _open_db(output_dir: Path) -> Path | None:
    db_path = output_dir / DEFAULT_DB_NAME
    if not db_path.exists():
        print(f"[!] No database at {db_path}. Run a crawl first.", file=sys.stderr)
        return None
    return db_path


def _rule(title: str) -> None:
    print("\n" + "=" * 72)
    print(f" {title}")
    print("=" * 72)


def mode_correlate(args: argparse.Namespace, storage: Storage, cfg: Config | None = None) -> int:
    """Score, and optionally verify, onion -> clearnet infrastructure links."""
    from darkosint.correlation import CorrelationEngine

    engine = CorrelationEngine(storage, config=cfg)
    findings = engine.run(persist=True, min_confidence=args.min_confidence)

    if args.verify or args.ct_lookup:
        route = "real IP" if args.verify_direct else "Tor"
        print(f"[*] Checking up to {args.llm_limit} candidate(s) against the clearnet "
              f"(via {route})…")
        for finding in findings[: args.llm_limit]:
            if args.verify:
                engine.verify(finding, direct=args.verify_direct)
            if args.ct_lookup:
                engine.enrich_from_ct(finding)
        findings.sort(key=lambda f: -f.confidence)

    _rule("CLEARNET CORRELATION")
    if not findings:
        print("  No onion -> clearnet correlations found.")
        print("  This is the expected result when no hidden service in the database")
        print("  served a certificate, a banner, or an artifact that also appears")
        print("  on a clearnet host.")
    for finding in findings:
        print("\n" + finding.explain())
        if args.llm_assess:
            _print_assessment(_llm().assess_correlation(finding))
    print(f"\n{len(findings)} finding(s).")
    return 0


def mode_graph(args: argparse.Namespace, storage: Storage) -> int:
    """Resolve identifiers into actors and optionally export the graph."""
    from darkosint.graph import ActorGraph, DEFAULT_EDGE_THRESHOLD

    threshold = (
        args.edge_threshold if args.edge_threshold is not None else DEFAULT_EDGE_THRESHOLD
    )
    graph = ActorGraph(storage, edge_threshold=threshold)
    actors = graph.build()
    graph.persist()

    _rule(f"ACTOR GRAPH  (edge threshold {threshold:.2f})")
    print(
        f"  {len(graph.nodes)} identifier node(s), "
        f"{len([e for e in graph.edges if e.weight >= threshold])} edge(s) kept, "
        f"{len(actors)} actor(s) resolved."
    )
    shown = [a for a in actors if a.confidence >= args.min_confidence]
    for actor in shown:
        print("\n" + actor.explain())
        if args.llm_assess:
            _print_assessment(_llm().assess_actor(actor))
    if not shown:
        print("\n  No actor clusters met the confidence floor.")
        print("  An actor needs at least two identifiers linked by evidence; a")
        print("  corpus of isolated identifiers correctly resolves to nothing.")

    if args.export:
        path = Path(args.export)
        suffix = path.suffix.lower()
        if suffix == ".graphml":
            payload = graph.to_graphml()
        elif suffix == ".dot":
            payload = graph.to_dot()
        else:
            payload = graph.to_json()
        path.write_text(payload, encoding="utf-8")
        print(f"\n[+] Graph written to {path} ({suffix.lstrip('.') or 'json'} format)")
    return 0


def mode_stylometry(args: argparse.Namespace, storage: Storage) -> int:
    """Rank handle pairs by writing-style similarity."""
    from darkosint.stylometry import (
        STANDOUT_SIGMA, STYLOMETRY_MIN_SCORE, StylometryEngine,
    )

    engine = StylometryEngine(storage)
    results = engine.run(min_score=0.0, persist=True)

    _rule("STYLOMETRIC AUTHORSHIP ATTRIBUTION")
    if not results:
        print("  Not enough attributed text to compare.")
        print("  Stylometry needs >= 2 handles with attributed post text; the")
        print("  generic parser cannot attribute text to an author, so this")
        print("  requires a site-specific parser (see parsers/example_market.py).")
        return 0

    print(f"  {len(engine.profiles)} handle(s) profiled, {len(results)} pair(s) compared.")
    print(f"  A pair is a lead at score >= {STYLOMETRY_MIN_SCORE:.2f}, "
          f"or at >= {STANDOUT_SIGMA}σ above the rest of this run.\n")
    for cmp_ in results:
        marker = "  >>" if cmp_.is_lead else "    "
        print(f"{marker} {cmp_.explain()}")
    print(
        "\n  Scores are similarities, not identities. A pair above the threshold "
        "is a lead for an analyst, not an attribution."
    )
    return 0


def mode_temporal(args: argparse.Namespace, storage: Storage) -> int:
    """Infer likely UTC offsets from observed activity times."""
    from darkosint.temporal import TemporalAnalyzer

    estimates = TemporalAnalyzer(storage).run()

    _rule("TEMPORAL / TIMEZONE INFERENCE")
    if not estimates:
        print("  No handles with parseable timestamps.")
        return 0
    for est in estimates:
        print(f"  {est.explain()}")
        if est.utc_offset is not None and est.histogram:
            peak = max(est.histogram) or 1.0
            bars = "".join(
                " ▁▂▃▄▅▆▇█"[min(8, int(v / peak * 8))] for v in est.histogram
            )
            print(f"      UTC hour 00→23: {bars}")
    print(
        "\n  Site timestamps are often rendered in the server's or viewer's "
        "timezone rather than the poster's. Treat this as a lead."
    )
    return 0


_LLM_SINGLETON = {}


def _llm():
    """Lazily build one shared LlmEnricher."""
    from darkosint.llm import LlmEnricher

    if "e" not in _LLM_SINGLETON:
        _LLM_SINGLETON["e"] = LlmEnricher()
    return _LLM_SINGLETON["e"]


def _print_assessment(data: dict) -> None:
    if not data or "error" in data:
        print(f"      [AI assessment unavailable: {data.get('error', 'unknown')}]")
        return
    print(f"      AI verdict : {data.get('verdict')} "
          f"(confidence {data.get('confidence')})")
    print(f"      strongest  : {data.get('strongest_link')}")
    print(f"      reasoning  : {data.get('reasoning')}")
    for alt in data.get("alternative_explanations", []):
        print(f"      alternative: {alt}")
    for item in data.get("what_would_falsify", []):
        print(f"      falsify by : {item}")


def mode_llm_enrich(args: argparse.Namespace, storage: Storage) -> int:
    """Extract self-disclosed claims from collected text using Claude."""
    from darkosint.llm import LlmEnricher

    enricher = LlmEnricher(storage)
    _rule("AI CLAIM EXTRACTION")
    if not enricher.available():
        print("  Claude is not available. Install the SDK and provide credentials:")
        print("      pip install anthropic")
        print("      export ANTHROPIC_API_KEY=...   (or run `ant auth login`)")
        return 2
    added = enricher.enrich_documents(limit=args.llm_limit)
    print(f"  {added} new claim(s) extracted and stored (all flagged heuristic).")
    print("  Query them with:  --query --type llm_opsec_slip")
    return 0


def mode_analyse(args: argparse.Namespace, output_dir: Path, cfg: Config | None = None) -> int:
    """Run the whole analysis chain in dependency order."""
    db_path = _open_db(output_dir)
    if db_path is None:
        return 1
    with Storage(db_path) as storage:
        if args.llm_enrich:
            mode_llm_enrich(args, storage)
        if args.correlate or args.analyse:
            mode_correlate(args, storage, cfg)
        if args.stylometry or args.analyse:
            mode_stylometry(args, storage)
        if args.temporal or args.analyse:
            mode_temporal(args, storage)
        # The graph runs last: it consumes the stylometry results.
        if args.graph or args.analyse:
            mode_graph(args, storage)
    return 0


# ---------------------------------------------------------------------------
# entrypoint
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(output_dir, verbose=args.verbose)

    cfg = resolve_config(args)

    if args.check_tor:
        return mode_check_tor(cfg)
    if args.query:
        return mode_query(args, output_dir)

    wants_analysis = any([args.analyse, args.correlate, args.graph, args.stylometry,
                          args.temporal, args.llm_enrich])

    # Live monitoring loop: re-crawl the seeds on a polite interval until stopped.
    if args.watch is not None:
        if not args.seeds:
            print("[!] --watch needs --seeds.", file=sys.stderr)
            return 1
        return mode_watch(cfg, args, output_dir)

    # A crawl and an analysis pass can be asked for together: collect first,
    # then analyse what was just collected, in one command.
    if args.seeds:
        rc = mode_crawl(cfg, args, output_dir)
        if rc != 0:
            return rc
        if wants_analysis:
            return mode_analyse(args, output_dir, cfg)
        return rc
    if wants_analysis:
        return mode_analyse(args, output_dir, cfg)

    build_parser().print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
