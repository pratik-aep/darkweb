"""SQLite storage and query API.

One self-contained database file (no external DB dependency) with tables for:
  * sources    — each fetched page (URL, host, site/parser, scan date, HTTP status)
  * snapshots  — references to the raw HTML saved on disk (path, sha256, size)
  * identifiers— extracted identifiers (type, value, context) linked to a source
  * links      — page->onion referral edges (the crawl/relationship graph)
  * actors / actor_identifiers — empty scaffolding for later analyst-driven
    linking of identifiers across sources into an actor graph

  * certificates — TLS certificates captured from hidden services (the clearnet
    correlation surface: CN/SAN, cert hash, and the SPKI hash that survives a
    certificate reissue)
  * pgp_keys   — parsed OpenPGP keys: fingerprint (the cross-market join key),
    UIDs, emails, names, subkeys
  * documents  — authored text samples, optionally attributed to a handle; the
    corpus the stylometric attribution runs over
  * correlations — scored onion -> clearnet infrastructure findings with evidence
  * actor_edges  — weighted, evidence-bearing edges between identifier nodes,
    from which the actor clusters are resolved
  * stylometry_pairs — scored authorship-similarity results between handles

The ``identifiers`` table is intentionally denormalized to (source_id, type,
value): the same value appearing under many sources is exactly the signal used
to pivot/link actors later, and the ``identifier_pivot`` view surfaces it.

Schema changes are additive and applied by :meth:`Storage._migrate`, so a
database created by an earlier version keeps its collected evidence.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from .extractors import Identifier

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    id              INTEGER PRIMARY KEY,
    url             TEXT NOT NULL,
    host            TEXT,
    site            TEXT,               -- parser/site name used
    scan_date       TEXT NOT NULL,      -- ISO-8601 UTC
    http_status     INTEGER,
    title           TEXT,
    depth           INTEGER,
    discovered_from TEXT                 -- parent URL, for provenance
);

CREATE TABLE IF NOT EXISTS snapshots (
    id             INTEGER PRIMARY KEY,
    source_id      INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    path           TEXT NOT NULL,        -- raw HTML file on disk
    sha256         TEXT,                 -- integrity / dedup
    content_length INTEGER,
    content_type   TEXT,
    saved_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS identifiers (
    id         INTEGER PRIMARY KEY,
    source_id  INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    type       TEXT NOT NULL,
    value      TEXT NOT NULL,
    context    TEXT,
    heuristic  INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    UNIQUE(source_id, type, value)
);

CREATE TABLE IF NOT EXISTS links (
    id            INTEGER PRIMARY KEY,
    source_id     INTEGER REFERENCES sources(id) ON DELETE CASCADE,
    from_url      TEXT,
    to_url        TEXT NOT NULL,
    kind          TEXT NOT NULL DEFAULT 'onion_ref',
    discovered_at TEXT NOT NULL
);

-- Scaffolding for later analyst-driven actor graph construction.
CREATE TABLE IF NOT EXISTS actors (
    id         INTEGER PRIMARY KEY,
    label      TEXT,
    notes      TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS actor_identifiers (
    actor_id        INTEGER NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    identifier_type TEXT NOT NULL,
    identifier_value TEXT NOT NULL,
    confidence      REAL,
    PRIMARY KEY (actor_id, identifier_type, identifier_value)
);

CREATE INDEX IF NOT EXISTS idx_identifiers_value ON identifiers(value);
CREATE INDEX IF NOT EXISTS idx_identifiers_type  ON identifiers(type);
CREATE INDEX IF NOT EXISTS idx_sources_host      ON sources(host);
CREATE INDEX IF NOT EXISTS idx_links_to_url      ON links(to_url);

-- TLS certificates observed on hidden services. The clearnet correlation
-- surface: a non-.onion name here is direct attribution, and spki_sha256
-- matches a clearnet host even after it renews its certificate.
CREATE TABLE IF NOT EXISTS certificates (
    id           INTEGER PRIMARY KEY,
    source_id    INTEGER REFERENCES sources(id) ON DELETE CASCADE,
    host         TEXT NOT NULL,
    port         INTEGER NOT NULL DEFAULT 443,
    sha256       TEXT,                 -- certificate fingerprint
    spki_sha256  TEXT,                 -- public key fingerprint (survives reissue)
    subject_cn   TEXT,
    issuer_cn    TEXT,
    serial       TEXT,
    not_before   TEXT,
    not_after    TEXT,
    san_dns      TEXT,                 -- JSON array
    san_ip       TEXT,                 -- JSON array
    self_signed  INTEGER NOT NULL DEFAULT 0,
    tls_version  TEXT,
    cipher       TEXT,
    observed_at  TEXT NOT NULL,
    UNIQUE(host, port, sha256)
);

-- Parsed OpenPGP keys. fingerprint is the cross-marketplace join key.
CREATE TABLE IF NOT EXISTS pgp_keys (
    id           INTEGER PRIMARY KEY,
    source_id    INTEGER REFERENCES sources(id) ON DELETE CASCADE,
    fingerprint  TEXT NOT NULL,
    key_id       TEXT,
    version      INTEGER,
    algorithm    TEXT,
    created      INTEGER,              -- key creation, unix seconds
    uids         TEXT,                 -- JSON array of raw UID strings
    emails       TEXT,                 -- JSON array
    names        TEXT,                 -- JSON array
    subkeys      TEXT,                 -- JSON array of subkey fingerprints
    checksum_ok  INTEGER NOT NULL DEFAULT 1,
    first_seen   TEXT NOT NULL,
    UNIQUE(source_id, fingerprint)
);

-- Authored text samples for stylometric attribution. handle may be NULL when
-- the generic parser could not attribute the text to an author.
CREATE TABLE IF NOT EXISTS documents (
    id         INTEGER PRIMARY KEY,
    source_id  INTEGER REFERENCES sources(id) ON DELETE CASCADE,
    handle     TEXT,
    text       TEXT NOT NULL,
    posted_at  TEXT,                   -- timestamp parsed out of the page, if any
    kind       TEXT NOT NULL DEFAULT 'page',
    created_at TEXT NOT NULL
);

-- Scored onion -> clearnet infrastructure findings, each carrying its evidence.
CREATE TABLE IF NOT EXISTS correlations (
    id              INTEGER PRIMARY KEY,
    onion_host      TEXT NOT NULL,
    indicator_type  TEXT NOT NULL,     -- identifier type that produced the match
    indicator_value TEXT NOT NULL,
    clearnet        TEXT NOT NULL,     -- the clearnet domain / IP implicated
    method          TEXT NOT NULL,     -- how it was established
    confidence      REAL NOT NULL,
    evidence        TEXT,              -- JSON: supporting detail for an analyst
    created_at      TEXT NOT NULL,
    UNIQUE(onion_host, indicator_type, indicator_value, clearnet, method)
);

-- Weighted, evidence-bearing edges between identifier nodes. Actor clusters are
-- resolved from these, so the reasoning behind every merge stays inspectable.
CREATE TABLE IF NOT EXISTS actor_edges (
    id          INTEGER PRIMARY KEY,
    a_type      TEXT NOT NULL,
    a_value     TEXT NOT NULL,
    b_type      TEXT NOT NULL,
    b_value     TEXT NOT NULL,
    weight      REAL NOT NULL,
    method      TEXT NOT NULL,
    evidence    TEXT,                  -- JSON
    created_at  TEXT NOT NULL,
    UNIQUE(a_type, a_value, b_type, b_value, method)
);

-- Stylometric authorship similarity between two handles.
CREATE TABLE IF NOT EXISTS stylometry_pairs (
    id          INTEGER PRIMARY KEY,
    handle_a    TEXT NOT NULL,
    handle_b    TEXT NOT NULL,
    score       REAL NOT NULL,
    method      TEXT NOT NULL,
    features    TEXT,                  -- JSON: per-feature contributions
    computed_at TEXT NOT NULL,
    UNIQUE(handle_a, handle_b, method)
);

CREATE INDEX IF NOT EXISTS idx_identifiers_value ON identifiers(value);
CREATE INDEX IF NOT EXISTS idx_identifiers_type  ON identifiers(type);
CREATE INDEX IF NOT EXISTS idx_sources_host      ON sources(host);
CREATE INDEX IF NOT EXISTS idx_links_to_url      ON links(to_url);
CREATE INDEX IF NOT EXISTS idx_certs_spki        ON certificates(spki_sha256);
CREATE INDEX IF NOT EXISTS idx_certs_host        ON certificates(host);
CREATE INDEX IF NOT EXISTS idx_pgp_fpr           ON pgp_keys(fingerprint);
CREATE INDEX IF NOT EXISTS idx_documents_handle  ON documents(handle);
CREATE INDEX IF NOT EXISTS idx_corr_onion        ON correlations(onion_host);
CREATE INDEX IF NOT EXISTS idx_edges_a           ON actor_edges(a_type, a_value);
CREATE INDEX IF NOT EXISTS idx_edges_b           ON actor_edges(b_type, b_value);

-- Cross-source pivot: which identifiers appear across how many distinct sources.
CREATE VIEW IF NOT EXISTS identifier_pivot AS
    SELECT type,
           value,
           COUNT(DISTINCT source_id) AS source_count,
           GROUP_CONCAT(DISTINCT source_id) AS source_ids
    FROM identifiers
    GROUP BY type, value;

-- Every onion host a given PGP fingerprint has been seen on: the single
-- clearest cross-marketplace actor signal in the database.
CREATE VIEW IF NOT EXISTS pgp_reuse AS
    SELECT k.fingerprint,
           COUNT(DISTINCT s.host) AS host_count,
           GROUP_CONCAT(DISTINCT s.host) AS hosts
    FROM pgp_keys k JOIN sources s ON s.id = k.source_id
    GROUP BY k.fingerprint;
"""

#: Columns added after the initial release, applied in place by ``_migrate``.
_ADDED_COLUMNS: dict[str, dict[str, str]] = {
    "sources": {
        # Full response headers as JSON: banners are evidence, and discarding
        # them was throwing away an entire identifier class.
        "response_headers": "TEXT",
        "final_url": "TEXT",
        "tls_checked": "INTEGER NOT NULL DEFAULT 0",
    },
    "actors": {
        "confidence": "REAL",
        "method": "TEXT",
        "evidence": "TEXT",
    },
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Storage:
    """Thin wrapper around a SQLite connection with the OSINT schema."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Apply additive column changes to a database created by an older build.

        ``CREATE TABLE IF NOT EXISTS`` cannot add a column to a table that already
        exists, so columns introduced after the initial release are added here.
        Purely additive: existing rows and collected evidence are never touched.
        """
        for table, columns in _ADDED_COLUMNS.items():
            existing = {
                row["name"]
                for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if not existing:
                continue  # table itself is new; CREATE TABLE already made it
            for name, decl in columns.items():
                if name not in existing:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

    # ---- writes -----------------------------------------------------------

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Cursor]:
        cur = self.conn.cursor()
        try:
            yield cur
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        finally:
            cur.close()

    def add_source(
        self,
        url: str,
        host: str,
        site: str,
        http_status: int | None,
        title: str | None = None,
        depth: int | None = None,
        discovered_from: str | None = None,
        response_headers: dict[str, str] | None = None,
        final_url: str | None = None,
        tls_checked: bool = False,
    ) -> int:
        """Record one fetched page.

        ``response_headers`` is stored verbatim as JSON: ``Server``,
        ``X-Powered-By``, ``ETag`` and friends are the "default service banner"
        evidence class, and they are only recoverable at fetch time.
        """
        with self._tx() as cur:
            cur.execute(
                """INSERT INTO sources
                   (url, host, site, scan_date, http_status, title, depth,
                    discovered_from, response_headers, final_url, tls_checked)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    url, host, site, _utcnow(), http_status, title, depth,
                    discovered_from,
                    json.dumps(response_headers) if response_headers else None,
                    final_url,
                    1 if tls_checked else 0,
                ),
            )
            return int(cur.lastrowid)

    def add_snapshot(
        self,
        source_id: int,
        path: str,
        sha256: str | None,
        content_length: int | None,
        content_type: str | None,
    ) -> int:
        with self._tx() as cur:
            cur.execute(
                """INSERT INTO snapshots
                   (source_id, path, sha256, content_length, content_type, saved_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (source_id, path, sha256, content_length, content_type, _utcnow()),
            )
            return int(cur.lastrowid)

    def add_identifiers(self, source_id: int, identifiers: Iterable[Identifier]) -> int:
        """Insert identifiers for a source; returns how many new rows were added."""
        now = _utcnow()
        added = 0
        with self._tx() as cur:
            for ident in identifiers:
                cur.execute(
                    """INSERT OR IGNORE INTO identifiers
                       (source_id, type, value, context, heuristic, first_seen)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        source_id,
                        ident.type,
                        ident.value,
                        ident.context,
                        1 if ident.heuristic else 0,
                        now,
                    ),
                )
                added += cur.rowcount
        return added

    def add_links(
        self, source_id: int, from_url: str, to_urls: Iterable[str], kind: str = "onion_ref"
    ) -> int:
        now = _utcnow()
        added = 0
        with self._tx() as cur:
            for to_url in to_urls:
                cur.execute(
                    """INSERT INTO links (source_id, from_url, to_url, kind, discovered_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (source_id, from_url, to_url, kind, now),
                )
                added += 1
        return added

    # ---- evidence: certificates, keys, documents --------------------------

    def add_certificate(self, source_id: int | None, observation) -> int | None:
        """Persist a :class:`~darkosint.tls_probe.TlsObservation`'s certificate."""
        cert = getattr(observation, "certificate", None)
        if cert is None:
            return None
        with self._tx() as cur:
            cur.execute(
                """INSERT OR IGNORE INTO certificates
                   (source_id, host, port, sha256, spki_sha256, subject_cn,
                    issuer_cn, serial, not_before, not_after, san_dns, san_ip,
                    self_signed, tls_version, cipher, observed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    source_id, observation.host, observation.port,
                    cert.sha256, cert.spki_sha256, cert.subject_cn, cert.issuer_cn,
                    cert.serial, cert.not_before, cert.not_after,
                    json.dumps(cert.san_dns), json.dumps(cert.san_ip),
                    1 if cert.self_signed else 0,
                    observation.tls_version, observation.cipher, _utcnow(),
                ),
            )
            return int(cur.lastrowid) if cur.rowcount else None

    def add_pgp_key(self, source_id: int, key) -> bool:
        """Persist a parsed :class:`~darkosint.pgp.PgpKey`. True if newly stored."""
        with self._tx() as cur:
            cur.execute(
                """INSERT OR IGNORE INTO pgp_keys
                   (source_id, fingerprint, key_id, version, algorithm, created,
                    uids, emails, names, subkeys, checksum_ok, first_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    source_id, key.fingerprint, key.key_id, key.version,
                    key.algorithm, key.created,
                    json.dumps([u.raw for u in key.uids]),
                    json.dumps(key.emails), json.dumps(key.names),
                    json.dumps(key.subkey_fingerprints),
                    1 if key.checksum_ok else 0, _utcnow(),
                ),
            )
            return cur.rowcount > 0

    def add_document(
        self,
        source_id: int,
        text: str,
        handle: str | None = None,
        posted_at: str | None = None,
        kind: str = "page",
    ) -> int:
        """Store an authored text sample for stylometric comparison."""
        with self._tx() as cur:
            cur.execute(
                """INSERT INTO documents
                   (source_id, handle, text, posted_at, kind, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (source_id, handle, text, posted_at, kind, _utcnow()),
            )
            return int(cur.lastrowid)

    # ---- analysis results -------------------------------------------------

    def clear_correlations(self) -> None:
        """Drop all stored correlation findings (recomputed wholesale each run)."""
        with self._tx() as cur:
            cur.execute("DELETE FROM correlations")

    def add_correlation(
        self,
        onion_host: str,
        indicator_type: str,
        indicator_value: str,
        clearnet: str,
        method: str,
        confidence: float,
        evidence: dict | None = None,
    ) -> bool:
        """Record one scored onion -> clearnet finding. True if newly added."""
        with self._tx() as cur:
            cur.execute(
                """INSERT OR IGNORE INTO correlations
                   (onion_host, indicator_type, indicator_value, clearnet,
                    method, confidence, evidence, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    onion_host, indicator_type, indicator_value, clearnet, method,
                    float(confidence), json.dumps(evidence or {}), _utcnow(),
                ),
            )
            return cur.rowcount > 0

    def add_actor_edge(
        self,
        a: tuple[str, str],
        b: tuple[str, str],
        weight: float,
        method: str,
        evidence: dict | None = None,
    ) -> bool:
        """Record a weighted link between two identifier nodes."""
        # Canonical ordering keeps (a,b) and (b,a) from becoming two rows.
        first, second = sorted([a, b])
        with self._tx() as cur:
            cur.execute(
                """INSERT OR IGNORE INTO actor_edges
                   (a_type, a_value, b_type, b_value, weight, method, evidence, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    first[0], first[1], second[0], second[1],
                    float(weight), method, json.dumps(evidence or {}), _utcnow(),
                ),
            )
            return cur.rowcount > 0

    def replace_actors(self, clusters: list[dict]) -> int:
        """Replace the resolved actor set with a freshly computed one.

        Actor resolution is deterministic from the evidence, so it is recomputed
        wholesale rather than incrementally patched; this keeps the stored graph
        consistent with the identifiers currently in the database.
        """
        with self._tx() as cur:
            cur.execute("DELETE FROM actor_identifiers")
            cur.execute("DELETE FROM actors")
            for cluster in clusters:
                cur.execute(
                    """INSERT INTO actors (label, notes, created_at, confidence, method, evidence)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        cluster.get("label"),
                        cluster.get("notes"),
                        _utcnow(),
                        cluster.get("confidence"),
                        cluster.get("method", "identifier-graph"),
                        json.dumps(cluster.get("evidence", [])),
                    ),
                )
                actor_id = int(cur.lastrowid)
                for type_, value, conf in cluster.get("members", []):
                    cur.execute(
                        """INSERT OR IGNORE INTO actor_identifiers
                           (actor_id, identifier_type, identifier_value, confidence)
                           VALUES (?, ?, ?, ?)""",
                        (actor_id, type_, value, conf),
                    )
            return len(clusters)

    def add_stylometry_pair(
        self,
        handle_a: str,
        handle_b: str,
        score: float,
        method: str,
        features: dict | None = None,
    ) -> bool:
        a, b = sorted([handle_a, handle_b])
        with self._tx() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO stylometry_pairs
                   (handle_a, handle_b, score, method, features, computed_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (a, b, float(score), method, json.dumps(features or {}), _utcnow()),
            )
            return True

    # ---- reads / queries --------------------------------------------------

    def counts_by_type(self) -> dict[str, int]:
        cur = self.conn.execute(
            "SELECT type, COUNT(*) AS n FROM identifiers GROUP BY type ORDER BY n DESC"
        )
        return {row["type"]: row["n"] for row in cur.fetchall()}

    def source_count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM sources").fetchone()[0])

    def find_by_value(self, value: str, exact: bool = False) -> list[sqlite3.Row]:
        """Find identifiers by value (exact or substring), joined to their source."""
        if exact:
            where, param = "i.value = ?", value
        else:
            where, param = "i.value LIKE ?", f"%{value}%"
        return self.conn.execute(
            f"""SELECT i.type, i.value, i.heuristic, i.context,
                       s.url, s.host, s.scan_date
                FROM identifiers i JOIN sources s ON s.id = i.source_id
                WHERE {where}
                ORDER BY i.type, s.scan_date""",
            (param,),
        ).fetchall()

    def find_handles(self, handle: str) -> list[sqlite3.Row]:
        """Find username-candidate identifiers matching a handle (substring)."""
        return self.conn.execute(
            """SELECT i.type, i.value, i.context, s.url, s.host, s.scan_date
               FROM identifiers i JOIN sources s ON s.id = i.source_id
               WHERE i.type = 'username_candidate' AND i.value LIKE ?
               ORDER BY s.scan_date""",
            (f"%{handle}%",),
        ).fetchall()

    def find_by_type(self, type_: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            """SELECT i.type, i.value, i.heuristic, s.url, s.host, s.scan_date
               FROM identifiers i JOIN sources s ON s.id = i.source_id
               WHERE i.type = ?
               ORDER BY s.scan_date""",
            (type_,),
        ).fetchall()

    def pivot(self, value: str) -> list[sqlite3.Row]:
        """All sources in which an exact identifier value appears (actor-graph seed)."""
        return self.conn.execute(
            """SELECT i.type, s.id AS source_id, s.url, s.host, s.scan_date
               FROM identifiers i JOIN sources s ON s.id = i.source_id
               WHERE i.value = ?
               ORDER BY s.scan_date""",
            (value,),
        ).fetchall()

    def shared_identifiers(self, min_sources: int = 2) -> list[sqlite3.Row]:
        """Identifiers observed across >= min_sources distinct sources."""
        return self.conn.execute(
            """SELECT type, value, source_count, source_ids
               FROM identifier_pivot
               WHERE source_count >= ?
               ORDER BY source_count DESC, type""",
            (min_sources,),
        ).fetchall()

    def list_sources(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            """SELECT id, url, host, site, http_status, scan_date, depth
               FROM sources ORDER BY id"""
        ).fetchall()

    def snapshots_for(self, source_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT path, sha256, content_length, saved_at FROM snapshots WHERE source_id = ?",
            (source_id,),
        ).fetchall()

    # ---- reads for the analysis layer -------------------------------------

    def sources_with_headers(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            """SELECT id, url, host, response_headers, http_status, final_url
               FROM sources WHERE response_headers IS NOT NULL"""
        ).fetchall()

    def certificates(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM certificates ORDER BY observed_at DESC"
        ).fetchall()

    def pgp_keys(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            """SELECT k.*, s.host, s.url
               FROM pgp_keys k LEFT JOIN sources s ON s.id = k.source_id
               ORDER BY k.first_seen"""
        ).fetchall()

    def pgp_reuse(self, min_hosts: int = 2) -> list[sqlite3.Row]:
        """PGP fingerprints seen on more than one host — cross-market reuse."""
        return self.conn.execute(
            "SELECT * FROM pgp_reuse WHERE host_count >= ? ORDER BY host_count DESC",
            (min_hosts,),
        ).fetchall()

    def documents(self, with_handle: bool = True) -> list[sqlite3.Row]:
        where = "WHERE d.handle IS NOT NULL AND d.handle != ''" if with_handle else ""
        return self.conn.execute(
            f"""SELECT d.id, d.handle, d.text, d.posted_at, d.kind,
                       s.host, s.url, s.id AS source_id
                FROM documents d LEFT JOIN sources s ON s.id = d.source_id
                {where}
                ORDER BY d.id"""
        ).fetchall()

    def identifiers_by_source(self) -> dict[int, list[sqlite3.Row]]:
        """All identifiers grouped by the source they were observed on."""
        out: dict[int, list[sqlite3.Row]] = {}
        for row in self.conn.execute(
            """SELECT source_id, type, value, heuristic, context
               FROM identifiers ORDER BY source_id"""
        ):
            out.setdefault(row["source_id"], []).append(row)
        return out

    def source_hosts(self) -> dict[int, str]:
        return {
            row["id"]: row["host"] or ""
            for row in self.conn.execute("SELECT id, host FROM sources")
        }

    def leaked_secrets(self) -> list[sqlite3.Row]:
        """Credential-shaped secrets detected in collected content.

        Values are stored hashed, so this returns the masked preview held in
        ``context`` rather than any plaintext — the plaintext lives only in the
        raw snapshot on disk.
        """
        return self.conn.execute(
            """SELECT i.type, i.value, i.context, s.host, s.url, i.first_seen
               FROM identifiers i JOIN sources s ON s.id = i.source_id
               WHERE i.type IN
                   ('secret_private_key','secret_api_token',
                    'secret_assignment','credential_pair')
               ORDER BY i.first_seen DESC""",
        ).fetchall()

    def correlations(self, min_confidence: float = 0.0) -> list[sqlite3.Row]:
        return self.conn.execute(
            """SELECT * FROM correlations WHERE confidence >= ?
               ORDER BY confidence DESC, onion_host""",
            (min_confidence,),
        ).fetchall()

    def actor_clusters(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            """SELECT a.id, a.label, a.confidence, a.method, a.evidence, a.notes,
                      COUNT(ai.identifier_value) AS member_count
               FROM actors a
               LEFT JOIN actor_identifiers ai ON ai.actor_id = a.id
               GROUP BY a.id ORDER BY member_count DESC, a.id"""
        ).fetchall()

    def actor_members(self, actor_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            """SELECT identifier_type, identifier_value, confidence
               FROM actor_identifiers WHERE actor_id = ?
               ORDER BY confidence DESC, identifier_type""",
            (actor_id,),
        ).fetchall()

    def actor_edges(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM actor_edges ORDER BY weight DESC"
        ).fetchall()

    def stylometry_pairs(self, min_score: float = 0.0) -> list[sqlite3.Row]:
        return self.conn.execute(
            """SELECT * FROM stylometry_pairs WHERE score >= ?
               ORDER BY score DESC""",
            (min_score,),
        ).fetchall()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Storage":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
