# darkosint — SIH Submission PPT Content Pack

Everything you need to build a strong Smart India Hackathon submission deck.
Sections below map to the standard SIH idea-submission template (title +
5 content slides). Lift bullets directly; speaker notes and anticipated Q&A are
at the end. Fill the `<>` placeholders with your actual problem-statement details.

> All technical claims here match the actual codebase (96 passing tests). Do not
> overclaim beyond this in the deck — judges probe, and honesty about a
> "leads-not-verdicts" tool is itself a strength.

---

## 0. Project identity (title slide)

- **Project name:** darkosint
- **One-line pitch:** *A passive dark-web OSINT and threat-actor
  de-anonymization toolkit that turns scattered onion-site artifacts into
  evidence-backed attribution leads.*
- **Tagline options (pick one):**
  - "From onion address to operator — with the evidence to prove it."
  - "De-anonymization as a chain of evidence, not a guess."
  - "Passive collection. Explainable attribution."
- **Problem Statement ID / Title:** `SH26151` — `<PS title>`
- **Organization / Ministry:** `<e.g. Ministry of Home Affairs / a CERT / police agency>`
- **Theme:** Blockchain & Cybersecurity (Dark Web Monitoring)
- **Team name & members:** `<fill>`

---

## 1. Proposed Solution (Slide 1)

**The problem (frame it sharply):**
- Criminal activity on the dark web — marketplaces, forums, leak sites — is
  deliberately anonymized via Tor. Investigators can *see* the content but
  struggle to link a hidden service or a handle back to a real operator.
- The intelligence is *there but scattered*: a PGP key on one market, the same
  wallet on another, a reused writing style, a TLS certificate that leaks a
  clearnet domain, a favicon shared with a surface-web site. No single artifact
  de-anonymizes anyone; the **links between them** do.
- Manual correlation across thousands of pages is slow, inconsistent, and hard
  to defend in a report.

**Our solution:**
- darkosint passively collects onion content over Tor, extracts every
  identifier, and runs an **analysis chain** that scores hypotheses like
  *"this hidden service runs on this clearnet host"* and *"these two handles are
  one person"* — each with a **confidence number and the evidence that produced
  it**.
- A live console shows an analyst, minute-to-minute, what has been collected and
  what has been linked.

**How it addresses the problem / innovation & uniqueness:**
- **Multi-signal fusion, not a single trick.** Infrastructure correlation +
  actor-graph entity resolution + stylometry + activity-timezone inference +
  cryptographic (PGP) linkage, combined with a **noisy-OR** model so independent
  weak signals reinforce without ever faking certainty.
- **Explainable by design.** Every finding expands to its evidence
  (`explain()`), so an analyst can defend a claim. This is the key differentiator
  vs. black-box tools.
- **Passive & safe.** It only reads what it is served — no logins, no exploiting,
  no active intrusion. This keeps it lawful and deployable by an agency.
- **Runs anywhere, no cloud dependency.** Pure-Python, single SQLite file, stdlib
  dashboard — an analyst clones and runs one command.

---

## 2. Technical Approach (Slide 2)

**Technology stack:**
- **Language:** Python 3.10+
- **Networking:** `requests` + `PySocks` over Tor **SOCKS5h** (DNS resolved
  inside Tor so no `.onion` lookups leak); `stem` for Tor control-port circuit
  rotation (NEWNYM).
- **Parsing:** `BeautifulSoup4` (stdlib `html.parser` backend).
- **Storage:** SQLite (single self-contained file; WAL mode) with an
  actor-graph-ready schema.
- **Dashboard:** Python stdlib `http.server` — zero build step, no `node_modules`,
  binds to `127.0.0.1`, self-updates every 2s.
- **Optional AI:** Anthropic Claude for natural-language claim extraction
  (lazily imported — everything else runs without it).
- **Testing:** `pytest` — **96 passing tests**.

**Architecture / data flow (redraw this as a diagram on the slide):**

```
 Seeds (.onion)
      │
      ▼
 ┌──────────────┐   passive GET over Tor (SOCKS5h)
 │  Tor Session │───────────────────────────────────────┐
 └──────────────┘   retries · backoff · politeness · rotation
      │
      ▼
 ┌──────────────┐   raw HTML snapshot to disk  ← evidentiary record
 │   Crawler    │───────────────────────────────► /snapshots
 └──────────────┘   frontier (BFS, depth/page bounded, host/visited-dedup)
      │
      ▼
 ┌──────────────┐   PGP · crypto wallets · emails · XMPP/Jabber · onions ·
 │  Extractors  │   clearnet URLs · leaked secrets (stored HASHED)
 └──────────────┘
      │
      ▼
 ┌──────────────────────── ANALYSIS CHAIN ────────────────────────┐
 │  Fingerprints  →  favicon mmh3, banners, analytics IDs, certs   │
 │  Correlation   →  onion → clearnet host  (noisy-OR scored)      │
 │  Actor Graph   →  identifiers → one operator (weighted edges)   │
 │  Stylometry    →  same author across handles                    │
 │  Temporal      →  UTC-offset / timezone inference               │
 │  LLM (opt.)    →  self-disclosed facts, OPSEC slips             │
 └────────────────────────────────────────────────────────────────┘
      │
      ▼
 ┌──────────────┐   SQLite  +  live analyst console  (leads + evidence)
 │   Storage /  │
 │  Dashboard   │
 └──────────────┘
```

**Methodology — the analysis techniques (your "wow" slide content):**

| Technique | What it does | Why it works |
|---|---|---|
| **Infrastructure correlation** | Scores "onion X runs on clearnet Y" | Combines TLS certs, server banners, **favicon hash (MurmurHash3, Shodan's convention)**, analytics IDs, leaked URLs via **noisy-OR** |
| **Actor entity-resolution graph** | Links identifiers into one operator | Typed, weighted, evidence-bearing edges: `pgp_uid` (cryptographic, near-certain), `co_occurrence` (damped by page crowding), `stylometry`, `trust_link` |
| **Stylometry** | "Are handle A and handle B the same author?" | Four independent feature families — **Cosine Delta** over char n-grams, function-word frequencies, structural/typographic signature, and **Burrows's Delta** (peer-reviewed) |
| **Temporal / timezone** | Infers an actor's UTC offset | 24-bin diurnal histogram of post times cross-correlated against a human sleep/wake curve across all 27 offsets (UTC-12…+14) |
| **PGP / X.509 / TLS** | Cryptographic identity anchors | Parses PGP User-ID packets; reads certificates (passively) that leak clearnet names |
| **Leaked-secret detection** | Flags exposed keys/tokens/combolists | High-specificity provider patterns; **stored as SHA-256 digests + masked previews, never plaintext** |

---

## 3. Feasibility and Viability (Slide 3)

**Feasibility (why it's buildable and already works):**
- **Working prototype exists** — full collection + analysis pipeline, live
  dashboard, offline demo with known ground truth, 96 automated tests passing.
- **Low resource footprint** — runs on a single analyst laptop; no cloud, no
  cluster, no paid infrastructure required for the core.
- **Dependency-light** — a handful of well-established Python libraries; optional
  enrichment (Shodan-compatible favicon hashing, crt.sh Certificate
  Transparency, Claude) degrades gracefully when absent.

**Challenges & how we handle them:**
| Challenge | Mitigation |
|---|---|
| Onion services are slow/unreachable | Retries with capped exponential backoff + jitter; failed fetches logged as errors, never silent |
| False positives poison attribution | Every score carries confidence + evidence; heuristic findings are chip-tagged; noisy-OR never reaches 1.0 |
| Monero is designed to resist tracing | XMR addresses are shape-validated only and flagged heuristic; the tool states its own limits |
| Handling sensitive/leaked data | Secrets stored hashed; plaintext only in the on-disk evidence snapshot; dashboard shows masked previews |
| Legal/ethical exposure | Strictly passive; authorized/public targets only; no target-site login or intrusion |

**Viability:** deployable today by a CERT / law-enforcement cyber cell / threat-
intel team as an internal, air-gappable investigation console.

---

## 4. Impact and Benefits (Slide 4)

**Who benefits:**
- Law-enforcement cyber units, CERTs, national threat-intelligence teams,
  financial-crime and anti-fraud investigators, brand/leak monitoring teams.

**Impact:**
- **Faster investigations** — automates the cross-page correlation an analyst
  would do by hand over days.
- **Defensible attribution** — every lead ships with its evidence trail, suitable
  for a report or escalation.
- **Early warning** — surfaces leaked national/corporate credentials and
  onion→clearnet exposures before they are exploited.
- **Consistency** — the same evidence produces the same scored conclusion, every
  run.

**Benefits (call out on slide):**
- **Social:** supports safer digital public infrastructure and victim protection.
- **Economic:** reduces investigation cost and time; pre-empts fraud losses.
- **Strategic:** an indigenous, self-hostable capability — no dependence on
  foreign SaaS for sensitive investigations.

---

## 5. Research and References (Slide 5)

- Tor Project — hidden-service architecture & Tor control protocol (`stem`).
- Burrows, J.F. — "Delta: a measure of stylistic difference" (authorship
  attribution).
- Standard stylometry: character n-grams + function words (Stamatatos, survey of
  authorship attribution methods).
- Shodan/Censys favicon-hash indexing (`http.favicon.hash`, MurmurHash3).
- Certificate Transparency / X.509 certificate correlation for infrastructure.
- Noisy-OR model for combining independent evidence (probabilistic reasoning).
- OWASP / secret-detection pattern conventions (provider key formats).
- `<add your PS's source docs / any datasets you cite>`

---

## Ethical & legal safeguards (keep a slide or a strong verbal note — judges WILL ask)

- **Passive-only:** issues GET requests and reads what is served; never logs in,
  submits forms, exploits, or probes for endpoints.
- **Authorized/public targets only:** intended for public dark-web content and
  systems the operator is authorized to investigate.
- **Privacy-preserving handling:** leaked secrets stored as hashes with masked
  previews; plaintext confined to the evidence snapshot.
- **Honest by construction:** presents *leads with confidence*, never a
  "TARGET IDENTIFIED" verdict; heuristic results are labelled.
- **Self-hostable / air-gappable:** binds to localhost; no third-party JS; no data
  leaves the analyst's machine unless they enable an external API.

*Framing tip: a de-anonymization tool that foregrounds its limits and safeguards
reads as mature and deployable — lean into this, don't hide it.*

---

## Prototype status / what to show as "results"

- End-to-end pipeline implemented; **96 automated tests pass**.
- **`python demo.py`** — runs the whole analysis chain on a synthetic corpus with
  **known ground truth** (two markets + a clearnet site, one operator under two
  handles sharing a PGP key, a cert leaking a clearnet domain, a shared analytics
  ID, two authors). Great for a live/screenshot demo — no Tor, no real target.
- Live dashboard (`dashboard.py`) — real-time collection console, self-updating,
  masked-secret rows, confidence meters (see `design.md` for the full UI spec).

**Screenshot suggestions for the deck:** (1) the dashboard mid-run, (2) an
onion→clearnet correlation row expanded to its evidence, (3) the actor graph /
resolved-actor panel, (4) the demo's ground-truth output.

---

## Future scope (optional slide / verbal)

- Actor relationship graph rendered interactively (Cytoscape.js — already
  designed in `design.md`).
- Server-Sent Events for push updates (design in place).
- Broader marketplace parsers; more chain-analysis providers; on-device NLP model
  to remove the hosted-LLM dependency.
- Multi-analyst case management and export to standard intel report formats.

---

## Slide-by-slide checklist (SIH template)

1. **Title** — name, tagline, PS ID/title, org, theme, team.
2. **Proposed Solution** — problem + solution + innovation/uniqueness (§1).
3. **Technical Approach** — stack + architecture diagram + methodology table (§2).
4. **Feasibility & Viability** — prototype status + challenges table (§3).
5. **Impact & Benefits** — audience + impact + social/economic/strategic (§4).
6. **Research & References** — sources (§5).

Keep each slide to ~5-6 bullets. Put the architecture diagram and the methodology
table on their own visual real estate — those two are what make judges remember
this project.

---

## Anticipated judge questions (prep these)

- *"How is this different from just Googling / existing OSINT tools?"* → Multi-
  signal fusion with explainable, scored attribution; most tools give raw data,
  not defensible links.
- *"Isn't scraping the dark web illegal / dangerous?"* → It is passive collection
  of public content over Tor, for authorized investigators; no intrusion, no
  target-site login; safeguards above.
- *"How accurate is it?"* → It outputs confidence-scored leads with evidence, not
  verdicts; noisy-OR keeps it honest; an analyst confirms. Accuracy is about
  *ranking the right lead to the top with its evidence*.
- *"Can it be fooled?"* → Yes (spoofed styles, bots, shared CDNs) — which is why
  every signal is independent and every score is explainable and reviewable.
- *"Why Monero results are weak?"* → We say so openly; Monero resists chain
  analysis by design. Stating limits is a feature.
- *"What's actually built vs. planned?"* → Full pipeline + 96 tests + offline demo
  are built; interactive graph UI and SSE are designed and next.
