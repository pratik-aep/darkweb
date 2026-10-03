#!/usr/bin/env python3
"""Live status dashboard for the darkosint collector.

A dependency-free-to-render (stdlib) web dashboard that reads the crawl's SQLite
database and audit log and renders a smoothly self-updating status page, so you
can watch — in real time — whether the collector is actively scraping and what
it has found so far.

It also exposes an interactive **scrape box**: paste any URL (onion or clearnet)
and it is fetched *through Tor* on demand using the same passive pipeline
(snapshot -> parse -> extract -> store), with results appearing live below.

The page loads once and then polls a small JSON endpoint (``/api/state``) every
2s, patching only the parts of the DOM that changed — so there is no full-page
reload, no flash, no scroll jump, and the input box never loses focus or text.

    python dashboard.py --output data/            # then open http://localhost:8787

Rendering is read-only; the scrape box performs single-page passive GETs only.
Bind stays on 127.0.0.1 — this is a local research console, not a public service.
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sqlite3
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Runtime-tunable via CLI (see main()); defaults here.
POLL_MS = 2000           # dashboard self-update interval, milliseconds
SCRAPE_TIMEOUT = 45.0    # seconds a single scrape waits before giving up
SCRAPE_RETRIES = 1       # retries on a failed/slow scrape

LOG_TAIL_LINES = 20
LOG_TAIL_BYTES = 16384   # only read the end of the log, not the whole file
ACTIVE_WINDOW_SECONDS = 90

try:
    from darkosint.config import Config
    from darkosint.crawler import Crawler
    from darkosint.storage import Storage
    from darkosint.tor_session import TorSession
    _SCRAPE_OK = True
    _SCRAPE_ERR = ""
except Exception as exc:  # noqa: BLE001
    _SCRAPE_OK = False
    _SCRAPE_ERR = f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# on-demand scrape jobs
# ---------------------------------------------------------------------------

_JOBS: list[dict] = []
_JOBS_LOCK = threading.Lock()
_MAX_JOBS = 25
#: Path to the operator's config.ini, so on-demand scrapes use the same Tor
#: settings as a real crawl instead of bare defaults. Set in main().
_CONFIG_PATH: str | None = None


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url
    return url


def run_scrape(raw_url: str, output_dir: Path, db_path: Path) -> None:
    """Fetch a single URL through Tor via the passive pipeline; record a job."""
    url = _normalize_url(raw_url)
    job = {
        "url": url, "status": "running", "started": time.time(), "finished": None,
        "error": "", "http_status": None, "identifiers": 0, "id_types": "",
    }
    with _JOBS_LOCK:
        _JOBS.insert(0, job)
        del _JOBS[_MAX_JOBS:]

    if not _SCRAPE_OK:
        job["status"], job["error"] = "error", f"scrape unavailable: {_SCRAPE_ERR}"
        job["finished"] = time.time()
        return
    try:
        try:
            base_cfg = Config.load(_CONFIG_PATH)  # honour the operator's Tor settings
        except Exception:  # noqa: BLE001 - fall back to defaults if no/bad config
            base_cfg = Config()
        cfg = base_cfg.with_overrides(**{
            "http.max_retries": SCRAPE_RETRIES, "http.timeout": SCRAPE_TIMEOUT,
            "http.per_host_delay": 0.0, "tor.rotate_every": 0,
            "crawl.max_pages": 1, "crawl.max_depth": 0, "crawl.expand_frontier": False,
        })
        session = TorSession(cfg)
        try:
            store = Storage(db_path)
            try:
                Crawler(cfg, session, store, output_dir).crawl([url])
                row = store.conn.execute(
                    "SELECT id, http_status FROM sources WHERE url=? ORDER BY id DESC LIMIT 1",
                    (url,),
                ).fetchone()
                if row:
                    job["http_status"] = row["http_status"]
                    job["identifiers"] = store.conn.execute(
                        "SELECT COUNT(*) FROM identifiers WHERE source_id=?", (row["id"],)
                    ).fetchone()[0]
                    types = store.conn.execute(
                        "SELECT type, COUNT(*) n FROM identifiers WHERE source_id=? "
                        "GROUP BY type ORDER BY n DESC", (row["id"],)
                    ).fetchall()
                    job["id_types"] = ", ".join(f"{t['type']}:{t['n']}" for t in types)
                job["status"] = "done"
            finally:
                store.close()
        finally:
            session.close()
    except Exception as exc:  # noqa: BLE001
        job["status"], job["error"] = "error", f"{type(exc).__name__}: {exc}"
    finally:
        job["finished"] = time.time()


# ---------------------------------------------------------------------------
# data access (read-only)
# ---------------------------------------------------------------------------

def _connect(db_path: Path) -> sqlite3.Connection | None:
    if not db_path.exists():
        return None
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _scalar(conn: sqlite3.Connection, sql: str, params=()) -> int:
    row = conn.execute(sql, params).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def gather(conn: sqlite3.Connection) -> dict:
    return {
        "sources": _scalar(conn, "SELECT COUNT(*) FROM sources"),
        "ok_sources": _scalar(conn, "SELECT COUNT(*) FROM sources WHERE http_status=200"),
        "identifiers": _scalar(conn, "SELECT COUNT(*) FROM identifiers"),
        "links": _scalar(conn, "SELECT COUNT(*) FROM links"),
        "exposures": _scalar(conn, "SELECT COUNT(*) FROM identifiers WHERE type='exposure_note'"),
        "by_type": conn.execute(
            "SELECT type, COUNT(*) n FROM identifiers GROUP BY type ORDER BY n DESC"
        ).fetchall(),
        "recent_sources": conn.execute(
            "SELECT id,url,host,site,http_status,scan_date,depth FROM sources "
            "ORDER BY id DESC LIMIT 12"
        ).fetchall(),
        "recent_ids": conn.execute(
            "SELECT i.type,i.value,i.heuristic,s.host FROM identifiers i "
            "JOIN sources s ON s.id=i.source_id ORDER BY i.id DESC LIMIT 18"
        ).fetchall(),
        "shared": conn.execute(
            "SELECT type,value,source_count FROM identifier_pivot WHERE source_count>=2 "
            "ORDER BY source_count DESC, type LIMIT 15"
        ).fetchall(),
        "certs": _scalar(conn, "SELECT COUNT(*) FROM certificates"),
        "pgp": _scalar(conn, "SELECT COUNT(DISTINCT fingerprint) FROM pgp_keys"),
        "actors": _scalar(conn, "SELECT COUNT(*) FROM actors"),
        "correlations": conn.execute(
            "SELECT onion_host, clearnet, confidence, method FROM correlations "
            "ORDER BY confidence DESC LIMIT 12"
        ).fetchall(),
        "top_corr": conn.execute(
            "SELECT MAX(confidence) FROM correlations"
        ).fetchone()[0],
        "actor_rows": conn.execute(
            "SELECT a.id, a.label, a.confidence, COUNT(ai.identifier_value) n "
            "FROM actors a LEFT JOIN actor_identifiers ai ON ai.actor_id=a.id "
            "GROUP BY a.id ORDER BY n DESC, a.confidence DESC LIMIT 12"
        ).fetchall(),
        "cert_rows": conn.execute(
            "SELECT host, subject_cn, issuer_cn, san_dns, self_signed "
            "FROM certificates ORDER BY observed_at DESC LIMIT 10"
        ).fetchall(),
        "key_rows": conn.execute(
            "SELECT k.fingerprint, k.key_id, k.uids, s.host FROM pgp_keys k "
            "LEFT JOIN sources s ON s.id=k.source_id ORDER BY k.id DESC LIMIT 10"
        ).fetchall(),
        "secrets": conn.execute(
            "SELECT i.type, i.context, s.host FROM identifiers i "
            "JOIN sources s ON s.id=i.source_id WHERE i.type IN "
            "('secret_private_key','secret_api_token','secret_assignment','credential_pair') "
            "ORDER BY i.id DESC LIMIT 20"
        ).fetchall(),
        "secret_count": _scalar(conn,
            "SELECT COUNT(*) FROM identifiers WHERE type IN "
            "('secret_private_key','secret_api_token','secret_assignment','credential_pair')"),
        "last_scan": conn.execute("SELECT MAX(scan_date) FROM sources").fetchone()[0],
    }


def seconds_since(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        then = datetime.fromisoformat(iso)
    except ValueError:
        return None
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - then).total_seconds()


def tail(path: Path, n: int) -> list[str]:
    """Read only the last LOG_TAIL_BYTES of the file, not the whole thing."""
    if not path.exists():
        return []
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - LOG_TAIL_BYTES))
            data = f.read().decode("utf-8", "replace")
    except OSError:
        return []
    return data.splitlines()[-n:]


# ---------------------------------------------------------------------------
# fragment rendering (shared by first paint and /api/state)
# ---------------------------------------------------------------------------

def _banner(data: dict, db_missing: bool) -> str:
    if db_missing:
        return ('<div class="banner idle"><span class="dot"></span>'
                'No database yet — paste a URL below to scrape your first page.</div>')
    secs = seconds_since(data.get("last_scan"))
    if secs is None:
        return ('<div class="banner idle"><span class="dot"></span>'
                'No pages scanned yet.</div>')
    if secs <= ACTIVE_WINDOW_SECONDS:
        return (f'<div class="banner active"><span class="dot"></span>'
                f'ACTIVELY SCRAPING — last page {secs:.0f}s ago</div>')
    label = f"{secs:.0f}s" if secs < 120 else f"{secs/60:.1f} min"
    return (f'<div class="banner idle"><span class="dot"></span>'
            f'Idle — last page {label} ago</div>')


def _cards(data: dict) -> str:
    out = ""
    top = data.get("top_corr")
    for n, label in [
        (data.get("sources", 0), "pages scanned"),
        (data.get("identifiers", 0), "identifiers"),
        (data.get("certs", 0), "TLS certs"),
        (data.get("pgp", 0), "PGP keys"),
        (data.get("actors", 0), "actors resolved"),
        (data.get("secret_count", 0), "leaked secrets"),
        (f"{float(top):.2f}" if top else "—", "top correlation"),
        (data.get("exposures", 0), "exposures noted"),
    ]:
        out += f'<div class="card"><div class="n">{n}</div><div class="l">{label}</div></div>'
    return out


def _jobs_inner() -> str:
    with _JOBS_LOCK:
        jobs = list(_JOBS[:12])
    if not jobs:
        return '<div class="muted">No manual scrapes yet.</div>'
    now = time.time()
    rows = []
    for j in jobs:
        age = (j["finished"] or now) - j["started"]
        st = j["status"]
        if st == "done":
            detail = (f'HTTP {j["http_status"]} · {j["identifiers"]} ids'
                      + (f' ({html.escape(j["id_types"])})' if j["id_types"] else ""))
        elif st == "error":
            detail = html.escape(j["error"])[:90]
        else:
            detail = "fetching through Tor…"
        rows.append(
            f'<tr><td><span class="pill {st}">{st}</span></td>'
            f'<td class="mono">{html.escape(j["url"][:70])}</td>'
            f'<td class="mono muted">{detail}</td>'
            f'<td class="muted">{age:.0f}s</td></tr>'
        )
    return ('<table><thead><tr><th>status</th><th>url</th><th>result</th><th>took</th>'
            f'</tr></thead><tbody>{"".join(rows)}</tbody></table>')


def _rows_by_type(rows) -> str:
    if not rows:
        return '<tr><td class="muted" colspan="2">none yet</td></tr>'
    mx = max(r["n"] for r in rows) or 1
    return "".join(
        f'<tr><td>{html.escape(r["type"])}</td>'
        f'<td style="width:55%">{r["n"]}<div class="bar">'
        f'<span style="width:{int(100*r["n"]/mx)}%"></span></div></td></tr>'
        for r in rows
    )


def _rows_sources(rows) -> str:
    if not rows:
        return '<tr><td class="muted" colspan="4">none yet</td></tr>'
    out = []
    for r in rows:
        st = r["http_status"]
        color = "#57e08a" if st == 200 else ("#e0576b" if st else "#e0b657")
        out.append(
            f'<tr><td style="color:{color}">{st if st is not None else "—"}</td>'
            f'<td>{r["depth"]}</td>'
            f'<td class="mono">{html.escape((r["host"] or "")[:34])}</td>'
            f'<td class="mono muted">{html.escape((r["url"] or "")[:52])}</td></tr>'
        )
    return "".join(out)


def _rows_ids(rows) -> str:
    if not rows:
        return '<tr><td class="muted" colspan="3">none yet</td></tr>'
    out = []
    for r in rows:
        cls = "tag exposure" if r["type"] == "exposure_note" else (
            "tag heur" if r["heuristic"] else "tag")
        val = r["value"] or ""
        val = val if len(val) <= 60 else val[:57] + "…"
        out.append(
            f'<tr><td><span class="{cls}">{html.escape(r["type"])}</span></td>'
            f'<td class="mono">{html.escape(val)}</td>'
            f'<td class="mono muted">{html.escape((r["host"] or "")[:26])}</td></tr>'
        )
    return "".join(out)


def _rows_correlations(rows) -> str:
    if not rows:
        return ('<tr><td colspan="3" class="muted">No onion&rarr;clearnet links yet. '
                'Run <code>--correlate</code> after a crawl.</td></tr>')
    out = []
    for r in rows:
        conf = float(r["confidence"] or 0)
        cls = "hit" if conf >= 0.85 else ("warn" if conf >= 0.5 else "")
        out.append(
            f'<tr><td class="mono">{html.escape((r["onion_host"] or "")[:26])}…</td>'
            f'<td class="mono"><span class="tag {cls}">{html.escape(r["clearnet"] or "")}</span></td>'
            f'<td>{conf:.2f}<div class="bar"><span style="width:{conf*100:.0f}%"></span></div>'
            f'<div class="muted" style="font-size:10.5px">{html.escape((r["method"] or "")[:60])}</div></td></tr>'
        )
    return "".join(out)


def _rows_actors(rows) -> str:
    if not rows:
        return ('<tr><td colspan="3" class="muted">No actors resolved yet. '
                'Run <code>--graph</code> after a crawl.</td></tr>')
    out = []
    for r in rows:
        conf = float(r["confidence"] or 0)
        out.append(
            f'<tr><td class="mono">{html.escape(r["label"] or "?")}</td>'
            f'<td>{r["n"]} ids</td>'
            f'<td>{conf:.2f}<div class="bar"><span style="width:{conf*100:.0f}%"></span></div></td></tr>'
        )
    return "".join(out)


def _rows_certs(rows) -> str:
    if not rows:
        return ('<tr><td colspan="3" class="muted">No TLS certificates captured. '
                'Certificates are read from https:// pages automatically.</td></tr>')
    out = []
    for r in rows:
        try:
            san = ", ".join(json.loads(r["san_dns"] or "[]"))
        except (json.JSONDecodeError, TypeError):
            san = ""
        names = [n for n in san.split(", ") if n and not n.endswith(".onion")]
        leak = ('<span class="tag exposure">CLEARNET NAME</span> '
                if names and (r["host"] or "").endswith(".onion") else "")
        ss = '<span class="tag heur">self-signed</span>' if r["self_signed"] else ""
        out.append(
            f'<tr><td class="mono">{html.escape((r["host"] or "")[:26])}…</td>'
            f'<td class="mono">{leak}{html.escape(r["subject_cn"] or "-")} {ss}</td>'
            f'<td class="mono muted">{html.escape(san[:60])}</td></tr>'
        )
    return "".join(out)


def _rows_secrets(rows) -> str:
    if not rows:
        return ('<tr><td colspan="3" class="muted">No leaked credentials or secrets '
                'detected in collected content. This surfaces secrets that pages '
                '<em>served</em> — it does not fetch anything behind a login.</td></tr>')
    labels = {
        "secret_private_key": "private key", "secret_api_token": "API token",
        "secret_assignment": "password/secret", "credential_pair": "credential pair",
    }
    out = []
    for r in rows:
        # context holds "LEAKED <label>: <masked preview> — <provenance>"
        ctx = r["context"] or ""
        preview = ctx.split("—")[0].replace("LEAKED", "").strip()
        out.append(
            f'<tr><td><span class="tag exposure">{labels.get(r["type"], r["type"])}</span></td>'
            f'<td class="mono">{html.escape(preview[:60])}</td>'
            f'<td class="mono muted">{html.escape((r["host"] or "?")[:30])}</td></tr>'
        )
    return "".join(out)


def _rows_keys(rows) -> str:
    if not rows:
        return ('<tr><td colspan="3" class="muted">No PGP keys parsed yet.</td></tr>')
    out = []
    for r in rows:
        try:
            uids = json.loads(r["uids"] or "[]")
        except (json.JSONDecodeError, TypeError):
            uids = []
        uid = html.escape(uids[0]) if uids else '<span class="muted">no User ID</span>'
        out.append(
            f'<tr><td class="mono">{html.escape(r["key_id"] or "")}</td>'
            f'<td class="mono">{uid}</td>'
            f'<td class="mono muted">{html.escape((r["host"] or "?")[:26])}</td></tr>'
        )
    return "".join(out)


def _rows_shared(rows) -> str:
    if not rows:
        return ('<tr><td class="muted" colspan="3">no identifiers seen across '
                'multiple sources yet</td></tr>')
    out = []
    for r in rows:
        val = r["value"] or ""
        val = val if len(val) <= 52 else val[:49] + "…"
        out.append(
            f'<tr><td><span class="tag">{html.escape(r["type"])}</span></td>'
            f'<td class="mono">{html.escape(val)}</td>'
            f'<td><b>{r["source_count"]}</b> sources</td></tr>'
        )
    return "".join(out)


def _fmt_log(lines: list[str]) -> str:
    out = []
    for ln in lines:
        e = html.escape(ln)
        if " GET " in ln or " -> " in ln:
            e = f'<span class="get">{e}</span>'
        elif "WARNING" in ln:
            e = f'<span class="warn">{e}</span>'
        elif "ERROR" in ln:
            e = f'<span class="err">{e}</span>'
        out.append(e)
    return "\n".join(out) if out else '<span class="muted">no log yet</span>'


def render_fragments(db_path: Path, log_path: Path) -> dict[str, str]:
    conn = _connect(db_path)
    db_missing = conn is None
    data: dict = {}
    if conn is not None:
        try:
            data = gather(conn)
        finally:
            conn.close()
    now = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    return {
        "sub": f"db: {html.escape(str(db_path))} · updating every {POLL_MS/1000:g}s · {now}",
        "banner": _banner(data, db_missing),
        "cards": _cards(data),
        "jobs": _jobs_inner(),
        "log": _fmt_log(tail(log_path, LOG_TAIL_LINES)),
        "bytype": _rows_by_type(data.get("by_type", [])),
        "shared": _rows_shared(data.get("shared", [])),
        "sources": _rows_sources(data.get("recent_sources", [])),
        "recentids": _rows_ids(data.get("recent_ids", [])),
        "correlations": _rows_correlations(data.get("correlations", [])),
        "actors": _rows_actors(data.get("actor_rows", [])),
        "certs": _rows_certs(data.get("cert_rows", [])),
        "keys": _rows_keys(data.get("key_rows", [])),
        "secrets": _rows_secrets(data.get("secrets", [])),
    }


# ---------------------------------------------------------------------------
# static page shell
# ---------------------------------------------------------------------------

_CSS = """
:root{color-scheme:dark;}*{box-sizing:border-box;}
body{margin:0;background:#0b0f14;color:#c9d4e0;font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}
.wrap{max-width:1100px;margin:0 auto;padding:20px 16px 60px;}
h1{font-size:20px;margin:0 0 2px;color:#e8eef5;letter-spacing:.5px;}
.sub{color:#5f6f80;font-size:12px;margin-bottom:18px;}
.banner{padding:12px 16px;border-radius:8px;font-weight:700;font-size:15px;display:flex;align-items:center;gap:10px;margin-bottom:16px;border:1px solid;transition:background .3s,border-color .3s,color .3s;}
.active{background:#0f2417;border-color:#1f7a44;color:#57e08a;}
.idle{background:#241a0f;border-color:#7a5a1f;color:#e0b657;}
.dot{width:10px;height:10px;border-radius:50%;background:currentColor;}
.active .dot{animation:pulse 1.1s infinite;}
@keyframes pulse{0%{opacity:1;}50%{opacity:.25;}100%{opacity:1;}}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px;}
.card{background:#111823;border:1px solid #1c2836;border-radius:8px;padding:14px 16px;}
.card .n{font-size:28px;font-weight:700;color:#e8eef5;}
.card .l{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:#5f6f80;margin-top:2px;}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;}
@media(max-width:820px){.grid2{grid-template-columns:1fr;}}
.panel{background:#0e141d;border:1px solid #1c2836;border-radius:8px;padding:14px 16px;margin-bottom:16px;}
.panel h2{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#7f93a8;margin:0 0 10px;}
.scrape{background:#0d1a1f;border-color:#1f4d5a;}.scrape h2{color:#57c8e0;}
.srow{display:flex;gap:10px;}
.srow input{flex:1;background:#060a0e;border:1px solid #24455a;border-radius:6px;color:#e8eef5;padding:11px 14px;font:inherit;outline:none;}
.srow input:focus{border-color:#3aa0d5;box-shadow:0 0 0 2px #12354a;}
.srow button{background:#1f7a9a;border:0;border-radius:6px;color:#eafcff;font:inherit;font-weight:700;padding:0 22px;cursor:pointer;letter-spacing:.5px;}
.srow button:hover{background:#2596bd;}.srow button:active{transform:translateY(1px);}
.hint{color:#4f6475;font-size:11.5px;margin-top:8px;}
table{width:100%;border-collapse:collapse;font-size:12.5px;}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid #16202c;vertical-align:top;}
th{color:#5f6f80;font-weight:600;font-size:11px;text-transform:uppercase;}
td.mono{word-break:break-all;}
.tag{display:inline-block;padding:1px 7px;border-radius:10px;font-size:10.5px;background:#152232;color:#7fb0e0;border:1px solid #24374d;}
.tag.exposure{background:#2a1520;color:#e07f9c;border-color:#4d2436;}
.tag.heur{background:#2a2415;color:#e0c07f;border-color:#4d4224;}
.tag.hit{background:#2a1520;color:#ff8fa8;border-color:#5d2a3e;font-weight:700;}
.tag.warn{background:#2a2415;color:#e0c07f;border-color:#4d4224;}
.pill{display:inline-block;padding:1px 9px;border-radius:10px;font-size:10.5px;font-weight:700;}
.pill.running{background:#2a2415;color:#e0c07f;animation:pulse 1.1s infinite;}
.pill.done{background:#0f2417;color:#57e08a;}.pill.error{background:#241014;color:#e0576b;}
.log{background:#080b0f;border:1px solid #1c2836;border-radius:8px;padding:12px;font-size:11.5px;white-space:pre-wrap;word-break:break-all;color:#8fa3b8;max-height:300px;overflow:auto;}
.log .get{color:#57e08a;}.log .warn{color:#e0b657;}.log .err{color:#e0576b;}
.bar{height:7px;background:#152232;border-radius:4px;overflow:hidden;margin-top:3px;}
.bar>span{display:block;height:100%;background:#3a7bd5;transition:width .4s;}
.muted{color:#5f6f80;}
#err{display:none;color:#e0576b;font-size:11px;margin-left:10px;}
"""

def _js() -> str:
    return """
<script>
(function(){
  var POLL=%d, failed=0;
  function typing(){var b=document.getElementById('urlbox');return b&&document.activeElement===b;}
  function set(id,v){var el=document.getElementById(id);if(el&&el.innerHTML!==v)el.innerHTML=v;}
  function apply(f){
    for(var k in f) set(k,f[k]);
    var lg=document.getElementById('log'); if(lg) lg.scrollTop=lg.scrollHeight;
    var e=document.getElementById('err'); if(e) e.style.display='none';
    failed=0;
  }
  function poll(){
    fetch('/api/state',{cache:'no-store'}).then(function(r){return r.json();})
      .then(apply).catch(function(){
        failed++; var e=document.getElementById('err');
        if(e&&failed>1){e.textContent='(dashboard server not responding)';e.style.display='inline';}
      });
  }
  function loop(){ if(!typing()) poll(); setTimeout(loop,POLL); }
  var form=document.getElementById('scrapeform');
  if(form) form.addEventListener('submit',function(ev){
    ev.preventDefault();
    var inp=document.getElementById('urlbox'), url=inp.value.trim();
    if(!url) return;
    fetch('/scrape',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:'url='+encodeURIComponent(url)})
      .then(function(){inp.value='';inp.blur();setTimeout(poll,250);setTimeout(poll,1200);})
      .catch(function(){});
  });
  setTimeout(poll,150); setTimeout(loop,POLL);
})();
</script>
""" % POLL_MS


def render_page(db_path: Path, log_path: Path) -> str:
    f = render_fragments(db_path, log_path)
    if _SCRAPE_OK:
        box = (
            '<form class="panel scrape" id="scrapeform" autocomplete="off" method="POST" action="/scrape">'
            '<h2>Scrape a URL now — fetched through Tor</h2>'
            '<div class="srow"><input id="urlbox" name="url" spellcheck="false" '
            'placeholder="https://example.com   or   http://xxxxxxxx.onion/page">'
            '<button type="submit">Scrape</button></div>'
            '<div class="hint">Single-page passive GET. Onion or clearnet — all traffic exits '
            'via Tor. Results appear below in a second or two. Updates pause only while you type here.'
            '</div></form>'
        )
    else:
        box = (f'<div class="panel scrape"><h2>Scrape a URL</h2><div class="hint">'
               f'Unavailable in this process: {html.escape(_SCRAPE_ERR)}<br>'
               f'Run the dashboard from the venv: <code>./.venv/bin/python dashboard.py</code>'
               f'</div></div>')
    return f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>darkosint — live status</title><style>{_CSS}</style></head>
<body><div class="wrap">
<h1>darkosint · live collection console<span id="err"></span></h1>
<div class="sub" id="sub">{f['sub']}</div>
<div id="banner">{f['banner']}</div>
{box}
<div class="cards" id="cards">{f['cards']}</div>
<div class="panel"><h2>Scrape jobs</h2><div id="jobs">{f['jobs']}</div></div>
<div class="panel"><h2>Live audit log (tail)</h2><div class="log" id="log">{f['log']}</div></div>
<div class="grid2">
  <div class="panel"><h2>Onion &rarr; clearnet correlations</h2>
    <table><thead><tr><th>hidden service</th><th>clearnet</th><th>confidence</th></tr></thead>
    <tbody id="correlations">{f['correlations']}</tbody></table></div>
  <div class="panel"><h2>Resolved actors</h2>
    <table><thead><tr><th>actor</th><th>size</th><th>confidence</th></tr></thead>
    <tbody id="actors">{f['actors']}</tbody></table></div>
</div>
<div class="grid2">
  <div class="panel"><h2>TLS certificates</h2>
    <table><thead><tr><th>host</th><th>subject CN</th><th>SAN</th></tr></thead>
    <tbody id="certs">{f['certs']}</tbody></table></div>
  <div class="panel"><h2>PGP keys &amp; User IDs</h2>
    <table><thead><tr><th>key id</th><th>User ID</th><th>host</th></tr></thead>
    <tbody id="keys">{f['keys']}</tbody></table></div>
</div>
<div class="panel"><h2>Exposed credentials &amp; secrets — leaked in collected content (passive)</h2>
  <table><thead><tr><th>type</th><th>masked preview</th><th>source host</th></tr></thead>
  <tbody id="secrets">{f['secrets']}</tbody></table>
  <div class="hint">Detected in content the crawl was <em>served</em> — private keys,
  API tokens, credential dumps left exposed. Values are stored hashed and shown masked;
  the tool never authenticates or fetches anything behind a login.</div></div>
<div class="grid2">
  <div class="panel"><h2>Identifiers by type</h2>
    <table><thead><tr><th>type</th><th>count</th></tr></thead>
    <tbody id="bytype">{f['bytype']}</tbody></table></div>
  <div class="panel"><h2>Shared across sources (actor-graph signal)</h2>
    <table><thead><tr><th>type</th><th>value</th><th>seen</th></tr></thead>
    <tbody id="shared">{f['shared']}</tbody></table></div>
</div>
<div class="panel"><h2>Recent pages</h2>
  <table><thead><tr><th>status</th><th>depth</th><th>host</th><th>url</th></tr></thead>
  <tbody id="sources">{f['sources']}</tbody></table></div>
<div class="panel"><h2>Recent identifiers</h2>
  <table><thead><tr><th>type</th><th>value</th><th>host</th></tr></thead>
  <tbody id="recentids">{f['recentids']}</tbody></table></div>
{_js()}
</div></body></html>"""


# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------

#: The only hostnames a request may claim. The console binds to loopback, so a
#: request whose Host is anything else is a DNS-rebinding attempt — a web page
#: that resolved its own domain to 127.0.0.1 to reach this port from a browser.
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def make_handler(db_path: Path, log_path: Path, output_dir: Path):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, body: bytes, ctype: str, code: int = 200) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _deny(self, code: int, why: str) -> None:
            body = why.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _host_is_local(self) -> bool:
            """Reject a Host header that is not loopback (DNS-rebinding guard)."""
            host = self.headers.get("Host", "")
            if not host:  # HTTP/1.0 with no Host: no rebinding vector
                return True
            hostname = host.rsplit(":", 1)[0].strip("[]").lower()
            return hostname in _LOOPBACK_HOSTS

        def _origin_is_local(self) -> bool:
            """Reject a state-changing request whose Origin is another site.

            A browser always sends Origin on a cross-site POST, so a page on
            evil.com submitting to this port is caught here. A non-browser client
            (curl, the operator's own tooling) sends none, and is allowed — it is
            not the cross-site-request vector this guards against.
            """
            origin = self.headers.get("Origin")
            if not origin:
                return True
            try:
                hostname = (urllib.parse.urlsplit(origin).hostname or "").lower()
            except ValueError:
                return False
            return hostname in _LOOPBACK_HOSTS

        def do_GET(self):  # noqa: N802
            if not self._host_is_local():
                return self._deny(403, "forbidden: non-local Host header")
            if self.path.startswith("/api/state"):
                body = json.dumps(render_fragments(db_path, log_path)).encode("utf-8")
                self._send(body, "application/json; charset=utf-8")
            elif self.path in ("/", "/index.html"):
                self._send(render_page(db_path, log_path).encode("utf-8"),
                           "text/html; charset=utf-8")
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):  # noqa: N802
            if not self._host_is_local():
                return self._deny(403, "forbidden: non-local Host header")
            if self.path != "/scrape":
                self.send_response(404)
                self.end_headers()
                return
            # The scrape box makes this console fetch an arbitrary URL over Tor
            # and write the result into the evidence DB, so it must not be
            # driveable by another site open in the same browser.
            if not self._origin_is_local():
                return self._deny(403, "forbidden: cross-origin scrape request")
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length).decode("utf-8", "replace")
            url = (urllib.parse.parse_qs(raw).get("url") or [""])[0].strip()
            if url:
                threading.Thread(target=run_scrape, args=(url, output_dir, db_path),
                                 daemon=True).start()
            # 303 works for both the JS fetch and a no-JS native form submit.
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()

        def log_message(self, *args):
            pass

    return Handler


def main() -> int:
    p = argparse.ArgumentParser(description="Live dashboard for darkosint.")
    p.add_argument("--output", "-o", default="data")
    p.add_argument("--config", metavar="FILE",
                   help="config.ini to use for on-demand scrapes (Tor settings).")
    p.add_argument("--db")
    p.add_argument("--log")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--poll", type=float, default=2.0,
                   help="Dashboard self-update interval in seconds (default 2, min 0.5).")
    p.add_argument("--timeout", type=float, default=45.0,
                   help="Scrape timeout in seconds per attempt (default 45).")
    p.add_argument("--retries", type=int, default=1,
                   help="Scrape retries on failure/slow site (default 1).")
    args = p.parse_args()

    global POLL_MS, SCRAPE_TIMEOUT, SCRAPE_RETRIES, _CONFIG_PATH
    POLL_MS = int(max(0.5, args.poll) * 1000)
    SCRAPE_TIMEOUT = max(1.0, args.timeout)
    SCRAPE_RETRIES = max(0, args.retries)
    _CONFIG_PATH = args.config

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    db_path = Path(args.db) if args.db else out / "osint.db"
    log_path = Path(args.log) if args.log else out / "audit.log"

    server = ThreadingHTTPServer((args.host, args.port),
                                 make_handler(db_path, log_path, out))
    print(f"[*] Dashboard on http://{args.host}:{args.port}  (reading {db_path})")
    print(f"[*] Refresh every {POLL_MS/1000:g}s · scrape timeout {SCRAPE_TIMEOUT:g}s · "
          f"{SCRAPE_RETRIES} retries")
    print(f"[*] Interactive scraping: {'ENABLED' if _SCRAPE_OK else 'DISABLED — ' + _SCRAPE_ERR}")
    print("[*] Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Dashboard stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
