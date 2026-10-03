# CLAUDE.md — project context & handoff

Orientation for a Claude Code session working in this repo. Read top to bottom
before making changes.

## What this project is

`darkosint` — a modular, terminal-based toolkit for **passive** dark web
threat-intelligence collection and threat-actor de-anonymization. It crawls
onion services over Tor, snapshots what it is served, extracts identifiers, and
runs an analysis chain (infrastructure correlation, actor-graph entity
resolution, stylometry, temporal/timezone inference, optional LLM enrichment) to
produce **attribution leads with confidence scores and evidence** — never bare
verdicts. A stdlib live dashboard (`dashboard.py`) renders the run in real time.

## Non-negotiable guardrails (do not cross these)

1. **Passive collection only.** Issue GET requests, save what is served, extract.
   Never log in, submit forms, brute-force, or probe for admin endpoints. The one
   sanctioned active step is a TLS handshake to read a certificate — already
   gated in `tls_probe.py` (on for https already fetched, off by default for
   http-only hosts). Keep it that way.
2. **Authorized / public targets only.** This toolkit is for public onion
   content and systems the user owns or is scoped to test. Do **not** help point
   it at third-party login portals, attendance/student systems, or any gated
   system without explicit authorization. (This came up in-session and was
   declined — hold that line.)
3. **No target-site authentication.** Nothing here authenticates against
   markets/forums or other gated target sites. Credential handling is strictly
   for the system's own outbound API integrations.
4. **Secrets stay hashed.** Leaked-credential findings are stored as `sha256:`
   digests + masked previews, never plaintext. The plaintext lives only in the
   raw on-disk snapshot (the evidentiary record). Preserve this discipline.
5. **Leads, not verdicts.** Every scored finding carries its confidence and its
   evidence (`explain()`). Never present an attribution as certain.

## Layout

- `darkosint/` — the package:
  - `config.py` (layered config), `logging_setup.py` (audit log), `tor_session.py`
    (Tor SOCKS5h + retries + circuit rotation), `crawler.py` (frontier/orchestration),
    `extractors.py` (regex/heuristic identifiers), `parsers/` (per-site + generic),
    `storage.py` (SQLite schema + query API).
  - Analysis: `correlation.py` (onion→clearnet, noisy-OR), `graph.py` (actor
    resolution), `stylometry.py` (authorship), `temporal.py` (timezone),
    `fingerprints.py` (favicon/banner/analytics keys), `pgp.py`, `x509.py`,
    `tls_probe.py`, `llm.py` (optional Claude enrichment, lazily imported).
  - `secrets.py` — **leaked-secret DETECTOR** (finds keys/tokens/combolists in
    collected content). NOT a credential manager. See cleanup items below.
- `scraper.py` — CLI (crawl / query / check-tor). `dashboard.py` — live console.
- `demo.py` + `demo_data/` — offline synthetic demo with known ground truth
  (no Tor, no network, no real people). Use this to exercise the analysis chain.
- `design.md` — dashboard design spec (theme tokens, IA, component inventory).
- `tests/` — 96 passing tests.

## Running

The bundled `.venv/` was rebuilt on Python 3.13 (it previously pointed at a
Command Line Tools 3.9 that no longer exists — recreate with
`python3 -m venv --clear .venv && .venv/bin/pip install -r requirements.txt`
if it breaks again). Tests:

```
python -m pytest tests/ -q      # expect 105 passing
python demo.py                  # offline analysis demo + scorecard, seeds ./demo_data
```

`demo.py` now plants decoys (a vendor-directory index, two vendors sharing a
footer contact) and prints a PASS/FAIL scorecard grading precision and recall
against the planted ground truth — the fastest way to confirm the analysis chain
still resolves the real links without inventing phantom actors.

## Hardening done 2026-09-18 (graph + secrets + dashboard)

- **Actor graph no longer over-merges.** `graph.py`: co-occurrence never links
  two identifiers of the same *strong* type (a directory of keys is a listing,
  not one person); boilerplate identifiers (recurring on most of a host's pages)
  are damped; and union refuses to fuse two components that each hold a distinct
  PGP key-identity on weak (co-occurrence/stylometry/trust) evidence alone.
  Cluster confidence is now the *weakest necessary link* (max-spanning-tree
  bottleneck), and each member carries a per-member `attachment` score, so a
  near-certain key+email core and a loosely-attached wallet are distinguishable.
- **Leaked plaintext no longer reaches the DB.** `secrets.py` gained
  `redact_secrets()`; the crawler redacts the served text *before* parsing/
  storing it, so `documents.text`, identifier context windows, and LLM
  enrichment never see the plaintext — it remains only in the raw on-disk
  snapshot. Digests are now HMAC-keyed (a per-install key under `~/.darkosint/`,
  or `$DARKOSINT_SECRET_HMAC_KEY`) so combolist hashes are not dictionary-
  reversible, and `mask()` reveals nothing of secrets under 12 chars.
- **Dashboard is CSRF/rebinding-hardened.** `dashboard.py` rejects non-loopback
  `Host` headers and cross-origin `POST /scrape`, so another site open in the
  same browser can no longer drive the scrape box (curl/operator tooling still
  works). Restart any running dashboard to pick this up.

## Live fetching & forum attribution (third pass, 2026-09-18)

- **Real Tor crawl verified working.** `scraper.py --check-tor` confirms exit;
  a bounded crawl of the public seeds pulled real identifiers + correlations.
- **`--watch SECS` live-monitoring loop** added: re-crawls the seeds on a polite
  interval (min 30s), reporting the +pages/+identifiers delta each pass, Ctrl-C
  to stop. Run e.g. `scraper.py --seeds seeds.txt -o live_demo --watch 90` and
  point `dashboard.py -o live_demo` at it to watch it fill.
- **Forum post attribution** (`parsers/forum.py`, used by `GenericParser`):
  recovers `(handle, post, timestamp)` from stock phpBB-style markup, strips
  quoted text, and emits quote→reply trust edges — so stylometry and temporal
  analysis now work on real forum crawls, not only seeded data. Tests: **108**.

## Also completed 2026-09-18 (second pass)

- **`--verify` goes through Tor by default.** `CorrelationEngine(storage, config=…)`
  probes the candidate clearnet host over Tor; `--verify-direct` opts into the
  real-IP path with a warning. `--seeds` + an analysis flag now crawl **then**
  analyse in one command. Correlation findings are recomputed wholesale each run
  (`Storage.clear_correlations()`) instead of accumulating. The dashboard scrape
  box honours `config.ini` via `dashboard.py --config`. Tests: **106 passing**.
- **SIH deck corrected** (`SIH_PPT_CONTENT.md`): stylometry described as Cosine
  Delta (not "TF-IDF"), XMPP not "Matrix", Shodan-favicon/crt.sh not
  Shodan/Censys/Etherscan integrations, Monero stated as shape-validated only,
  and locale-dedup reworded to host/visited-dedup.
- **Interactive actor-graph board** built as a shareable artifact from
  `demo_data/actor_graph.json` (click-through evidence, decoy-rejection spotlight).

## Known cleanup (do only if asked)

1. **Rename `darkosint/secrets.py`** → e.g. `exposed_secrets.py`. It still shadows
   Python's stdlib `secrets` (it detects leaks; it does not manage the system's own
   API keys). Update the import in `crawler.py`. (Dead code already removed.)
2. **Site-specific forum parsers** (phpBB/MyBB/XenForo/SMF) so stylometry and
   temporal analysis work on real crawls, not just the demo — the biggest
   remaining capability gain.
3. **Feed `temporal.activity_similarity` into the actor graph** as a weak
   corroborating edge (currently computed but never used by `graph.py`).

## Context notes

- This is the **canonical** copy. A second, diverged copy exists at
  `/Users/pratiksmac/Downloads/darkweb ` (original). Work here only; do not edit
  the other copy unless explicitly asked. Note: the API-**credential-management**
  module (`.env` / `.env.example` / typed fail-fast config, for the system's own
  Shodan/Censys/Etherscan/etc. keys) currently lives only in that other copy and
  is **not** present here — port it if credential management is needed.
- Overall review verdict: architecture and methods are sound; the ethical posture
  is real and verified (hash-only storage confirmed in the live DB). The items
  above are tidy-ups, not correctness bugs.
