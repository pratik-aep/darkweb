# darkosint console — design specification

**Status:** proposal · **Scope:** the live investigation console (`dashboard.py`) ·
**Audience:** whoever builds or restyles the frontend for this project.

This document is the design brief for the dashboard. It records *what the console
is for*, *how the frontend should be structured*, and *the exact theme tokens to
build against*. It reflects the app as it stands today (a dependency-free,
server-rendered console that self-updates every 2 s) and the direction it should
grow in — not a rewrite for its own sake.

---

## 1. What this screen is, and who is at it

It is an **analyst's operations console during a live de-anonymization**, not a
report and not a marketing page. One person is watching a crawl run and asking,
minute to minute: *is it still collecting? what has it linked? what is worth my
attention right now?* Every design decision answers to that person.

That framing has consequences the rest of this document follows from:

- **It is scanned and operated, not read top-to-bottom.** The craft is
  information design, not prose typography. The summary comes before the detail;
  state is encoded in *form* (a severity stripe, a confidence meter, a pill) so
  the one thing that needs attention reads at a glance, without parsing a number.
- **Trust is the product.** This tool makes attribution *claims*. An analyst will
  act on them, and may have to defend them. So the interface never shows a verdict
  without its confidence and its evidence one click away. A bare "these are the
  same actor" with no "because" is worse than useless here — it is a liability.
- **It runs in a dim room for long sessions.** Dark-first is a genuine fit, not a
  fashion choice — but it has to be a *designed* dark, not black with a neon pop.
- **It handles sensitive material.** Leaked credentials are shown masked; the
  interface must never itself become the place a live secret is displayed in the
  clear.

---

## 2. Design principles

1. **Situational awareness first.** The top of the screen answers "is it working
   and what's the headline" before any table. Big-number tiles earn their place
   here — pages scanned, identifiers, top correlation, leaked secrets — because
   those figures *are* the point of the first glance.
2. **Confidence is always visible.** Any scored finding — a correlation, an actor
   cluster, a stylometry pair — carries its number *and* a visual tier. Numbers
   alone don't triage; a red 0.95 and a grey 0.20 must be distinguishable
   pre-attentively, from across a desk.
3. **Severity is not the accent.** The brand/accent hue (cyan) marks
   *interactive and identity* elements. The good/warning/critical scale is a
   separate, reserved set of hues that means exactly one thing: how alarmed to be.
   They never get spent on decoration.
4. **Evidence is one gesture away.** Every finding row expands to the edges that
   produced it — the whole `explain()` output the backend already generates. The
   console surfaces the conclusion; the reasoning is always retrievable.
5. **Calm under load.** A crawl produces a lot of movement. Updates patch in
   place — no full-page reload, no flash, no scroll jump, no input losing focus.
   Motion is reserved for the one thing that changed, and for the "actively
   scraping" pulse; everything else holds still.
6. **Honest empty states.** A zero is information. "No actors resolved — an actor
   needs ≥2 identifiers linked by evidence" teaches the analyst what the tool is
   doing, instead of showing a blank box that reads as broken.

---

## 3. Frontend architecture

### 3.1 The decision: stay zero-build, structure it better

The console today is a single stdlib `http.server` that renders HTML fragments and
is polled by ~40 lines of vanilla JS. **Keep that.** It is the right architecture
for this app, and the reasons are not laziness:

- **It runs from the same venv as the collector**, with no `node_modules`, no
  build step, no bundler — an analyst clones the repo and runs one command. A
  React/Vite frontend would add a toolchain to a tool whose whole value is that it
  runs anywhere the collector does.
- **The data source is a local SQLite file**, not a public API. There is no
  multi-client, multi-tenant, offline-sync problem that a framework would earn its
  weight solving.
- **The security posture benefits.** No third-party JS supply chain, no CDN, bound
  to `127.0.0.1`. For a tool that handles leaked credentials, "the frontend is
  ~200 lines of code you can read in full" is a feature.

So the architecture is **server-rendered fragments + a thin client that patches
the DOM**. What should change is *organization*, not stack:

```
dashboard.py
├── server         BaseHTTPRequestHandler: GET / , GET /api/state , POST /scrape
├── data layer     gather(conn)      one read per panel, returns plain rows
├── render layer   _rows_*(rows)     pure row -> HTML string, one per panel
│                   render_fragments  assembles the {panel_id: html} map
├── shell          render_page       static HTML skeleton + inline <style>/<script>
└── client (JS)    poll /api/state every 2s -> patch only changed #ids
```

The single rule that keeps this honest: **every panel is `(SQL rows) -> HTML
string`, a pure function.** First paint and every subsequent poll call the *same*
renderers. There is never a second code path where the initial page and the live
update can drift apart.

### 3.2 The update channel: move polling → Server-Sent Events

The 2 s poll works, but it is a fixed heartbeat: it costs a request when nothing
changed, and lags up to 2 s when something did. Since the server already knows
when a crawl writes to the DB, the better fit is **SSE** (`text/event-stream`):

- one long-lived `GET /api/stream`, the server pushes a fragment map when state
  changes (debounced ~500 ms) and a keepalive otherwise;
- the client's `EventSource` applies the same patch function it uses today;
- still stdlib, still one file, still no dependency — SSE is just a response that
  never closes.

Polling stays as the fallback for the one case SSE complicates (the on-demand
scrape job), and because a 2 s poll is a perfectly good degraded mode.

### 3.3 Client state model

The client owns almost no state — the server is the source of truth. What it does
own is strictly *per-viewer UI convenience*, and it lives in three places:

- **the DOM**, patched by `#id` from the fragment map (the live data);
- **`localStorage`**, wrapped in try/catch, for a remembered active tab, a
  collapsed panel, an unsent scrape-box draft — nothing that matters if it's lost;
- **an "actively typing" guard**, so a poll never rewrites the scrape box while
  the analyst is mid-URL. (This already exists and must survive any refactor.)

### 3.4 Rendering the actor graph

The one place a static table is the wrong tool is the **actor relationship
graph** — nodes (identifiers) and edges (evidence) are inherently spatial. The
backend already exports GraphML/DOT/JSON via `ActorGraph.to_dict()`. The console
should render that inline with a small force-directed view:

- **Cytoscape.js** (UMD, from cdnjs, pinned) is the right dependency to admit here
  — it is the one interaction the vanilla approach genuinely can't carry, and it
  reads the JSON the backend already produces.
- Nodes coloured by their type strength (cryptographic identity vs. handle),
  edges weighted and styled by method (solid PGP-UID, dashed stylometry), the
  cluster a click away from its `explain()` panel.

Everything else stays dependency-free.

---

## 4. Information architecture

The layout tells the investigation's own story, top to bottom — **collect →
correlate → resolve → attribute** — because that is the order the analyst reasons
in, and each stage consumes the one above it.

```
┌────────────────────────────────────────────────────────────┐
│  darkosint · live collection console          ● ACTIVE      │  status bar
├────────────────────────────────────────────────────────────┤
│  Scrape a URL now — fetched through Tor            [ Scrape ]│  action
├────────────────────────────────────────────────────────────┤
│  8 pages · 154 ids · 2 certs · 6 leaks · 0.99 top corr      │  vitals (tiles)
├────────────────────────────────────────────────────────────┤
│  ┌── Onion → clearnet ──────┐  ┌── Resolved actors ───────┐ │  ATTRIBUTION
│  │ market → shop.ex   0.99  │  │ PGP:F231…  7 ids   0.99   │ │  (the payoff —
│  └──────────────────────────┘  └───────────────────────────┘ │   highest first)
│  ┌── TLS certificates ──────┐  ┌── PGP keys & User IDs ────┐ │  EVIDENCE
│  │ market  CLEARNET NAME    │  │ F231…  Cass Ferrow <…>    │ │  (the raw
│  └──────────────────────────┘  └───────────────────────────┘ │   artifacts)
│  ┌── Exposed credentials & secrets (passive) ─────────────┐ │  SEVERITY
│  │ ⬤ private key  <PEM …>          leakforum…onion         │ │
│  └─────────────────────────────────────────────────────────┘ │
│  ┌── Identifiers by type ───┐  ┌── Shared across sources ──┐ │  RAW SIGNAL
│  ┌── Recent pages ──────────────────────────────────────────┐│
│  ┌── Live audit log (tail) ─────────────────────────────────┐│  PROVENANCE
└────────────────────────────────────────────────────────────┘
```

**Above the fold:** status, the scrape action, the vitals row, and the
attribution panels (correlations + actors). An analyst who looks for two seconds
should learn: *it's running, and here is the strongest thing it has concluded.*
Evidence, severity, raw signal, and the log fill in as they scroll — detail on
demand, never in the way.

Two structural notes:
- **The attribution panels lead** even though they are computed last, because a
  console surfaces conclusions first. The pipeline runs collect→attribute; the
  screen reads attribute→collect.
- **The log is last, not hidden.** It is the provenance trail — always available,
  never competing with the findings for the top of the screen.

---

## 5. Theme

A single committed **dark operations** theme, executed as a proper token set. It
is dark-first by deliberate choice (long sessions, dim rooms), so the tokens are
authored dark; a light variant is a phase-2 nicety, structured for but not
required. The neutral is **not** a pure grey — it carries a slight blue bias
toward the accent, so the surfaces read as *chosen*, not defaulted. The accent is
a restrained **cyan**, inherited from the console's existing scrape box, and it is
spent only on identity and interaction. The severity scale is a separate reserved
set that means alarm and nothing else.

Avoided on purpose: the acid-green-on-black "hacker terminal" cliché, the lone
neon pop, and the purple-gradient hero. This reads as an instrument, not a poster.

### 5.1 Color tokens

Author as CSS custom properties on `:root`. Every colour is a token; nothing is a
literal in a component.

```css
:root {
  /* ── ground: blue-biased neutrals, darkest to lightest ── */
  --bg:            #0b0f14;   /* app background — near-black, faint blue cast */
  --surface:       #111823;   /* panels, cards */
  --surface-2:     #0e141d;   /* recessed wells (tables, log) */
  --surface-input: #060a0e;   /* the darkest inset — inputs */
  --border:        #1c2836;   /* hairline separators */
  --border-strong: #24374d;   /* focused / emphasised edges */

  /* ── text ── */
  --text:          #e8eef5;   /* primary — headings, values */
  --text-body:     #c9d4e0;   /* body */
  --text-muted:    #5f6f80;   /* labels, captions, secondary */

  /* ── accent: cyan — identity & interaction ONLY ── */
  --accent:        #38b6d9;   /* links, focus rings, primary action */
  --accent-hover:  #52c8e6;
  --accent-dim:    #12354a;   /* accent-tinted fills, focus glow */

  /* ── semantic severity — reserved, never decorative ── */
  --ok:            #57e08a;   /* verified match, healthy, high confidence */
  --ok-bg:         #0f2417;
  --warn:          #e0b657;   /* heuristic, medium confidence, needs review */
  --warn-bg:       #241a0f;
  --crit:          #ff8fa8;   /* clearnet leak, exposed secret, critical */
  --crit-bg:       #2a1520;

  /* ── confidence ramp (correlation / actor scores) ── */
  --conf-high:     var(--crit);   /* ≥0.85 — a strong attribution IS the alarm */
  --conf-med:      var(--warn);   /* 0.50–0.85 */
  --conf-low:      var(--text-muted); /* <0.50 — a lead, not a finding */
}
```

**One deliberate inversion worth calling out:** on the confidence ramp, *high
confidence is red*, not green. In most dashboards green = good. Here, a
high-confidence de-anonymization is the thing the analyst most needs to see — it
is the alarm, not the all-clear. Green is reserved for `--ok`, which marks a
*verified* technical fact (a cryptographic certificate match), where "confirmed"
genuinely is reassurance about the evidence quality. The two scales are kept
visually distinct so this never reads as ambiguous.

### 5.2 Typography

Two roles, both from the one CSP-admitted host (Google Fonts), each with a real
fallback stack:

- **Interface & headings — `Inter`.** Neutral, dense, legible at small sizes,
  excellent tabular figures. The workhorse for labels, panel titles, and body.
- **Data & identifiers — `JetBrains Mono`.** Every fingerprint, wallet, onion
  address, cert hash and masked secret is monospace, so a 56-char base32 onion or
  a SHA-256 lines up character-for-character and can be visually compared down a
  column. This is non-negotiable in this domain: the reader's core task is
  *matching identifiers*, and proportional type makes that hostile.

```css
--font-ui:   'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
--font-mono: 'JetBrains Mono', ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
```

Type scale (restrained — this is an instrument, not an editorial page):

| role | size / line | weight | notes |
|---|---|---|---|
| big-number tile | 28 / 1.1 | 700 | `tabular-nums` |
| panel title | 12 / 1.2 | 600 | uppercase, `letter-spacing: 1px`, `--text-muted` |
| body / rows | 13 / 1.5 | 400 | |
| identifier (mono) | 12.5 / 1.4 | 400 | `word-break: break-all` for long hashes |
| label / caption | 11 / 1.4 | 600 | uppercase, muted |

Every column of digits gets `font-variant-numeric: tabular-nums` so counts and
confidences align on the decimal.

### 5.3 Spacing, radius, motion

- **Spacing:** a 4 px base scale — 4 / 8 / 12 / 16 / 24. Layout uses flex/grid
  `gap`, never per-element margins. A 16 px side gutter at every width.
- **Radius:** 8 px on panels and cards, 6 px on controls and pills. One step, so
  "rounded" doesn't become noise.
- **Elevation is spent by role, not stamped everywhere.** A flat 1 px `--border`
  is the default separator. A shadow lifts *only* the scrape box and any modal —
  the things that sit above the plane. Findings panels are peers; they get borders,
  not shadows, so nothing falsely reads as more important than its neighbour.
- **Motion, and its budget:** the "actively scraping" dot pulses (1.1 s); a newly
  arrived finding fades in once from a visible resting state; confidence bars
  animate their width on change (0.4 s). Everything else is instant. All of it is
  wrapped in `@media (prefers-reduced-motion: reduce)`, which drops to no
  animation. Motion here signals *state change worth noticing* — overspending it
  is exactly what makes a console feel frantic and AI-generated.

### 5.4 Encoding state in form

Semantic colour is paired with a non-colour cue so the console is legible to a
colour-blind analyst and readable in a screenshot:

- **Confidence** → a filled meter bar *and* the number, not colour alone.
- **Severity** → a leading stripe/dot *and* a text label ("CLEARNET NAME",
  "self-signed"), not a bare red cell.
- **Heuristic vs. confirmed** → a `[heuristic]` chip, so an unconfirmed lead is
  never mistaken for ground truth even in greyscale.

---

## 6. Component inventory

| component | role | notes |
|---|---|---|
| **status bar** | is it running? | pulsing dot + "ACTIVE / IDLE", last-page age |
| **vitals tile** | headline figures | big `tabular-nums`, quiet label; leaks & top-corr are the ones that spike |
| **finding row** | one scored hypothesis | onion → clearnet / actor, with confidence meter, expands to `explain()` |
| **confidence meter** | score at a glance | bar coloured by tier + number; the pre-attentive triage cue |
| **evidence drawer** | the "because" | the backend's `explain()` lines, method + weight per edge |
| **identifier cell** | any artifact | mono, `break-all`, copy-on-click |
| **severity tag** | leak / exposure / self-signed | stripe or dot + label, `--crit`/`--warn` |
| **masked-secret row** | leaked credential | type chip + `AKIA…MPLE` preview; never plaintext |
| **scrape box** | on-demand fetch | the one elevated, accent-bordered control; live job status below |
| **actor graph** | relationship map | Cytoscape, nodes by strength, edges by method |
| **log tail** | provenance | recessed well, colour-coded GET/WARN/ERR lines |

Compose each as one object: the finding rows share edges, baselines and inner
padding from the top of the list to the bottom, and the confidence meter sits in
the same place on every row.

---

## 7. Accessibility & responsiveness

- **Contrast:** body text on `--surface` clears WCAG AA; muted text is used only
  for genuinely secondary labels, never for data an analyst must read.
- **Keyboard:** every control has a visible focus ring (`--accent`, 2 px); the
  scrape box and expandable rows are keyboard-operable; findings expand on Enter.
- **Colour independence:** as §5.4 — every colour cue is doubled with shape or text.
- **Responsive:** the two-column panel grid collapses to one column below ~820 px;
  the vitals tiles wrap; wide tables (long onion addresses, hashes) get
  `overflow-x: auto` on their own container so the page body never scrolls
  sideways. Usable down to ~400 px, though the real target is a desk monitor.

---

## 8. Phased plan

1. **Tokenise the current dashboard.** Lift the existing inline styles onto the
   token set in §5.1 — no visual overhaul, just make the theme systematic and the
   confidence/severity colours semantic. Low risk, immediate payoff.
2. **Confidence meters + severity tags everywhere** a score or a leak appears, so
   triage becomes pre-attentive.
3. **Evidence drawers** — wire each finding row to expand to its `explain()`.
4. **SSE** in place of the 2 s poll, polling kept as fallback.
5. **The actor graph** via Cytoscape — the one real visual upgrade.
6. **Light theme** (optional) — the tokens already make it a swap, not a rewrite.

Each phase ships a working console; none requires a framework or a build step.

---

## 9. One thing not to do

Don't let the console outgrow its honesty. It is tempting to make a threat-intel
dashboard look authoritative — big confident verdicts, red everywhere, a
"TARGET IDENTIFIED" banner. This tool produces *leads with confidences*, and the
interface must keep saying so: the score, the `[heuristic]` chip, the
"this is a lead, not an attribution" line, the evidence one click down. A console
that looks more certain than the evidence is the one design failure that actually
matters here.
