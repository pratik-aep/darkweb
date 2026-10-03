# darkosint — dark web threat actor de-anonymization

A modular, terminal-based toolkit for **passive** threat-intelligence collection
from `.onion` services over Tor, and for the analysis that turns what it collects
into attribution leads.

Three capabilities, matching the three the problem statement calls for:

1. **Infrastructure de-anonymization** — capture TLS certificates, default
   service banners, favicon hashes and clearnet artifacts from hidden services,
   then correlate them against clearnet infrastructure with scored, evidence-
   bearing findings.
2. **Actor de-anonymization** — resolve handles, PGP keys, wallets and trust
   links observed across multiple marketplaces into a single relationship graph,
   with every merge justified by the evidence that produced it.
3. **AI-based analysis** — stylometric authorship attribution to link handles by
   writing style, timezone inference from activity patterns, and optional
   Claude-backed extraction of self-disclosed claims and review of each finding.

Collection is passive. Analysis is local. Everything that reaches the network
beyond the page fetch is opt-in and named.

> **Scope & ethics.** This is a *passive collection* tool for authorized threat
> intelligence work. It only issues `GET` requests and reads what it is served.
> It never logs in, submits forms, performs transactions, or acts on any
> misconfiguration it happens to observe — exposed endpoints (e.g. an Apache
> `/server-status` page) are **noted and logged, never probed or exploited**.
> Everything is logged for auditability. Use it only against targets you are
> authorized to collect from.

---

## Architecture

One responsibility per module — no single mega-script:

**Collection**

| Module | Responsibility |
| --- | --- |
| `darkosint/config.py` | Layered config: defaults → `config.ini` → CLI overrides |
| `darkosint/logging_setup.py` | Audit logging to console + rotating `audit.log` |
| `darkosint/tor_session.py` | `requests` over Tor SOCKS5h, retries + backoff, per-host politeness, circuit rotation via `stem`, full response-header capture |
| `darkosint/tls_probe.py` | TLS certificate capture through Tor (and direct, for the clearnet side) |
| `darkosint/extractors.py` | Identifier extraction + BTC base58check/bech32 validation |
| `darkosint/pgp.py` | OpenPGP parsing: fingerprints, User ID identities, subkeys |
| `darkosint/x509.py` | DER/X.509 parsing: CN, SAN, validity, cert and public-key hashes |
| `darkosint/fingerprints.py` | Banners, favicon hashing (MurmurHash3), clearnet artifacts |
| `darkosint/storage.py` | SQLite schema + query API, with in-place migration |
| `darkosint/parsers/` | `BaseParser` interface, generic fallback, per-site template, registry |
| `darkosint/crawler.py` | Frontier, fetching, snapshotting, evidence capture, orchestration |

**Analysis** (offline unless noted)

| Module | Responsibility |
| --- | --- |
| `darkosint/correlation.py` | Scores onion → clearnet hypotheses; optional live verification |
| `darkosint/graph.py` | Entity resolution into actors; JSON / GraphML / DOT export |
| `darkosint/stylometry.py` | Authorship attribution (Cosine Delta + Burrows's Delta) |
| `darkosint/temporal.py` | Timezone inference from activity-hour distributions |
| `darkosint/llm.py` | Claude-backed claim extraction and finding review (needs network) |

**Entrypoints**

| File | Purpose |
| --- | --- |
| `scraper.py` | CLI: crawl, query, and every analysis mode |
| `dashboard.py` | Live local console; on-demand single-page scrape |
| `demo.py` | Offline demonstration on synthetic data with known ground truth |

```
seeds.txt ─▶ frontier (BFS, depth/page-bounded, visited-tracked)
          ─▶ TorSession.get  (socks5h, retries, backoff, rotation, politeness)
          ─▶ raw snapshot to data/snapshots/<host>/<ts>_<sha>.html
          ─▶ per-site parser   ─▶ identifiers, onion links, documents, trust edges
          ─▶ evidence capture  ─▶ headers/banners, TLS certificate, favicon hash,
                                  clearnet artifacts, parsed PGP keys
          ─▶ SQLite
          ─▶ enqueue new onion links (if expansion enabled)

then, over what was collected:

  correlation ─▶ onion → clearnet findings, scored and evidenced
  stylometry  ─▶ handle-pair authorship similarity
  temporal    ─▶ per-handle UTC offset estimates
  graph       ─▶ actors: connected components over weighted, evidenced edges
  (optional)  ─▶ Claude: self-disclosed claims, and review of each finding
```

---

## Prerequisites

**1. Tor** must be running locally with a SOCKS proxy and (for circuit rotation)
a control port. On macOS with Homebrew:

```bash
brew install tor
```

Edit your `torrc` (e.g. `/opt/homebrew/etc/tor/torrc`) to enable the control port:

```
SOCKSPort 9050
ControlPort 9051
CookieAuthentication 1
```

Then run Tor:

```bash
tor            # foreground
# or: brew services start tor
```

> If you set a `HashedControlPassword` instead of cookie auth, put the matching
> plaintext password in `config.ini` under `[tor] control_password`.

**2. Python deps** (Python 3.10+):

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

`requests`, `PySocks`, `stem`, `beautifulsoup4`. (`PySocks`/`stem` are imported
lazily, so extraction, storage, and querying work even without them — only the
live Tor crawl needs them.)

---

## Usage

Verify Tor is actually carrying your traffic before a run:

```bash
python scraper.py --check-tor
```

Run a crawl:

```bash
python scraper.py --seeds seeds.txt --output data/
python scraper.py --seeds seeds.txt --output data/ --max-pages 20 --max-depth 1 --rotate-every 10
```

At the end it prints a summary (pages fetched, identifiers by type, exposures
noted). Everything lands under `--output`:

```
data/
├── osint.db                 # SQLite database
├── audit.log                # full audit trail
└── snapshots/<host>/…​.html  # raw page snapshots
```

### Querying results back out

```bash
python scraper.py --output data/ --query --stats
python scraper.py --output data/ --query --handle shadowseller
python scraper.py --output data/ --query --value 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --exact
python scraper.py --output data/ --query --type btc_address
python scraper.py --output data/ --query --pivot shadowseller     # all sources containing a value
python scraper.py --output data/ --query --shared 2               # identifiers seen across ≥2 sources
python scraper.py --output data/ --query --list-sources
```

`--pivot` and `--shared` surface the same identifier appearing across multiple
sites — the raw signal for linking identifiers into an actor/relationship graph.

Two more selectors cover the structured evidence:

```bash
python scraper.py --output data/ --query --certs   # TLS certificates, CN/SAN/hashes
python scraper.py --output data/ --query --keys    # PGP keys, User IDs, cross-host reuse
```

### Analysis

All of this runs offline over what was already collected. Nothing here contacts
a hidden service.

```bash
python scraper.py --output data/ --correlate      # onion -> clearnet, scored
python scraper.py --output data/ --graph          # resolve actors
python scraper.py --output data/ --stylometry     # authorship attribution
python scraper.py --output data/ --temporal       # timezone inference
python scraper.py --output data/ --analyse        # the whole chain, in order
```

Export the actor graph for Gephi, Cytoscape, yEd or Graphviz:

```bash
python scraper.py --output data/ --graph --export actors.json      # JSON
python scraper.py --output data/ --graph --export actors.graphml   # GraphML
python scraper.py --output data/ --graph --export actors.dot       # Graphviz
```

The three modes that **do** use the network are opt-in and say so:

```bash
# Connect to a candidate clearnet host and compare its certificate to the one
# the hidden service served. An exact match is the strongest finding available.
python scraper.py --output data/ --correlate --verify

# Query Certificate Transparency logs (public, clearnet) for the cert's CN.
python scraper.py --output data/ --correlate --ct-lookup

# Claude-backed analysis (needs `pip install anthropic` and an API key).
python scraper.py --output data/ --llm-enrich              # extract claims
python scraper.py --output data/ --graph --llm-assess      # review each actor
```

### Seeing it work without a crawl

```bash
python demo.py
```

Builds a synthetic corpus with known ground truth — one operator publishing the
same PGP key under two handles on two marketplaces, a certificate leaking a
clearnet domain, a shared analytics ID, and a second author sharing only a
writing style — then runs the full chain over it. No Tor, no network, no real
site. Useful for seeing the output shape before pointing the collector anywhere.

### Live console

```bash
python dashboard.py --output data/      # then open http://localhost:8787
```

---

## What gets extracted

| Type | Notes |
| --- | --- |
| `pgp_block` | Full armored public key blocks (stored by SHA-256; full key kept in context) |
| `pgp_fingerprint` | Grouped `xxxx xxxx …` (high-confidence) or contiguous 40-hex (flagged) |
| `btc_address` | Base58 **checksum-validated** + bech32/bech32m **checksum-validated** |
| `eth_address` | Shape-validated (`0x` + 40 hex); flagged — no keccak/EIP-55 check |
| `xmr_address` | Shape-validated Monero (95/106 chars); flagged |
| `email` / `xmpp` | Emails, and Jabber/XMPP IDs (explicit `xmpp:`/`jabber:` or keyword-adjacent) |
| `onion_url` | Other referenced `.onion` links (v2/v3) — also feed the frontier |
| `username_candidate` | Heuristic handles — **always flagged for analyst review, never ground truth** |
| `exposure_note` | Passive note that a page looks like an exposed endpoint — detection only |

Infrastructure evidence, for clearnet correlation:

| Type | Notes |
| --- | --- |
| `tls_cn` / `tls_san` | Names asserted by a hidden service's TLS certificate |
| `tls_fingerprint` | Certificate SHA-256 — exact cross-host match |
| `tls_spki` | **Public key** SHA-256 — survives certificate reissue, so it still matches a clearnet host that merely renewed |
| `clearnet_domain` | Non-`.onion` domain named by a certificate (strong) or referenced in markup (weak) |
| `server_banner` / `powered_by` | Default service banners from response headers; stock strings are flagged |
| `favicon_mmh3` | MurmurHash3 of the base64 favicon — the exact value Shodan indexes under `http.favicon.hash` |
| `analytics_id` | GA / GTM / AdSense / Pixel IDs — issued per *operator*, not per site |
| `etag` | Inode-style ETags, which encode a specific host's filesystem state |
| `s3_bucket`, `ipv4` | Bucket names and hardcoded public IPs left in markup |

Parsed from OpenPGP keys rather than hashed:

| Type | Notes |
| --- | --- |
| `pgp_fingerprint` | Derived from the key packet — the correct cross-marketplace join key |
| `email` / `pgp_uid_name` | The name and address inside the key's **User ID packet**, frequently the single most identifying artifact on a vendor page |

Inferred by AI analysis (always flagged, never ground truth):

| Type | Notes |
| --- | --- |
| `llm_claimed_location` | Places the text claims an actor lives in or ships from |
| `llm_alias_claim` | Handles an actor says they used previously |
| `llm_opsec_slip` | Statements that narrow who or where the actor is |
| `llm_claimed_language`, `llm_contact_pref`, `llm_vendor_role` | Supporting claims |

Identifiers marked *heuristic* / *flagged* need analyst confirmation.

---

## Adding a site-specific parser

Marketplace and forum HTML differ and change constantly, so parsing is per-site.
Copy `darkosint/parsers/example_market.py`, point `matches()` at the target host,
override `parse()` to pull that site's structured fields (then `super().parse()`
for the generic pass), and register the class in `darkosint/parsers/__init__.py`.

---

## Database schema (SQLite)

- **sources** — `url, host, site, scan_date, http_status, title, depth, discovered_from`
- **snapshots** — `source_id → sources`, `path, sha256, content_length, content_type, saved_at`
- **identifiers** — `source_id → sources`, `type, value, context, heuristic, first_seen` (UNIQUE per source/type/value)
- **links** — page→onion referral edges (the crawl/relationship graph)
- **certificates** — TLS certificates: CN, SAN, validity, cert hash, SPKI hash
- **pgp_keys** — parsed keys: fingerprint, key ID, UIDs, emails, names, subkeys
- **documents** — authored text samples, optionally attributed to a handle
- **correlations** — scored onion → clearnet findings with their evidence
- **actors / actor_identifiers** — resolved actor clusters and their members
- **actor_edges** — weighted, evidence-bearing links between identifier nodes
- **stylometry_pairs** — authorship similarity between two handles
- **identifier_pivot** (view) — each identifier value with its distinct source count
- **pgp_reuse** (view) — each PGP fingerprint and every host it was seen on

Because `identifiers` is keyed by `(source_id, type, value)`, the same value
across many sources is directly queryable — the foundation for the actor graph.
Schema changes are applied in place by `Storage._migrate`, so a database from an
earlier version keeps everything it collected.

---

## How the scoring works

Every finding carries a number and the evidence behind it, because an
unexplained score is useless to an analyst.

**Clearnet correlation.** Each method contributes an independent confidence
(`tls_clearnet_name` 0.95, `analytics_shared` 0.85, `favicon_shared` 0.70,
`banner_shared` 0.30, `clearnet_reference` 0.20, a verified live certificate
match 0.97). Where several methods implicate the same pair they combine with
noisy-OR — `1 − Π(1 − cᵢ)` — so independent weak signals reinforce without ever
reaching certainty, and one strong signal is not diluted by weak ones.

**Actor resolution.** Identifier types carry an explicit strength prior, from
`pgp_fingerprint` at 1.00 down to `onion_url` at 0.15. Co-occurrence edges are
damped by how crowded the page was: a vendor profile listing one key and one
handle is strong evidence, a forum index listing forty handles is almost none.
Clusters are connected components over edges above a threshold, and a cluster
with no cryptographically strong member is explicitly penalised — two handles
joined only by writing style score low, and should.

**Stylometry.** Cosine Delta over character n-grams and word frequencies,
standardized against the corpus, with Burrows's Delta as an independent
cross-check. Calibrated against 5 known authors in 3 disjoint samples each:
F1 0.857 at threshold 0.56 on 12,000-character samples. Because absolute scores
compress on short samples, a pair also qualifies by standing ≥2.5σ above every
other pair in its own run, which is scale-free. The measured numbers, including
where the method fails, are in the `darkosint/stylometry.py` docstring.

**Timezone inference.** The activity histogram is cross-correlated against a
reference diurnal curve at all 27 candidate offsets; confidence reflects how
decisively the best offset beat the runner-up, so a flat histogram — a bot, or a
shared account — correctly yields no confident answer.

---

## Tests

```bash
python -m pytest tests/ -q
```

78 tests, fully offline (no Tor, no network):

- `test_extractors.py` — extraction and BTC checksum validation
- `test_storage.py` — the storage and query API, including cross-source pivoting
- `test_parsers.py` — the parser interface and registry
- `test_pgp.py` — OpenPGP parsing, against a real key whose fingerprint is
  published, so the parser is checked against a known answer
- `test_x509.py` — DER/X.509 parsing and infrastructure fingerprints, including
  MurmurHash3 against published test vectors
- `test_analysis.py` — correlation scoring, graph resolution, stylometric
  measures, and timezone inference against synthetic actors with known offsets
- `test_integration.py` — the full chain against a corpus with planted ground
  truth, asserting each stage recovers what was planted

The X.509 parser was additionally checked against live certificates from three
public hosts, comparing every field against Python's own verified
`getpeercert()` output; the PGP parser against two real keys (Ed25519 and RSA)
retrieved by fingerprint from public keyservers.

---

## Configuration reference

See `config.ini` for all tunables: Tor proxy/control ports, circuit rotation
interval, retry/backoff, per-host politeness delay, crawl bounds (`max_pages`,
`max_depth`, frontier expansion, host scoping), and the `[evidence]` section
below. Any of them can be overridden per run from the CLI.

### What reaches the network, and when

The collection posture is passive, and the boundaries are explicit:

| Behaviour | Default | Contacts the target beyond the page fetch? |
| --- | --- | --- |
| Page fetch (`GET`) | always | — |
| Response-header capture | always | no — already served |
| TLS certificate on an `https://` page | **on** | no — the handshake happens anyway |
| TLS probe of port 443 on an `http://`-only host | **off** | **yes** — `--probe-tls` |
| Favicon fetch | **off** | **yes**, one extra `GET` — `--favicon` |
| Correlation, graph, stylometry, temporal | on/manual | no — local analysis only |
| Live clearnet certificate verification | **off** | clearnet host only — `--verify` |
| Certificate Transparency lookup | **off** | public CT logs only — `--ct-lookup` |
| Claude analysis | **off** | Anthropic API — `--llm-enrich` / `--llm-assess` |

The collector still never logs in, submits a form, transacts, or acts on any
misconfiguration it observes. An exposed endpoint is noted and logged; it is
never probed or exploited.
