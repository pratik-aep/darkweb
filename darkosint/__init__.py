"""darkosint — dark web threat actor de-anonymization toolkit.

Collection
----------
- config          : layered configuration (defaults <- file <- CLI)
- logging_setup   : audit logging to console + rotating file
- tor_session     : requests over Tor SOCKS5h, retries, backoff, per-host
                    politeness, circuit rotation via stem, header capture
- tls_probe       : TLS certificate capture through Tor, and directly for the
                    clearnet side of a correlation
- extractors      : identifier extraction (PGP, crypto, contacts, onions) with
                    base58check and bech32 checksum validation
- pgp             : OpenPGP parsing — fingerprints, User ID identities, subkeys
- x509            : DER/X.509 parsing — CN, SAN, validity, cert and SPKI hashes
- fingerprints    : service banners, favicon hashing, clearnet artifacts
- storage         : SQLite schema, query API, and in-place migration
- parsers         : BaseParser interface, generic fallback, per-site template
- crawler         : frontier, fetching, snapshotting, evidence capture

Analysis
--------
- correlation     : scores onion -> clearnet hypotheses from collected evidence
- graph           : entity resolution into actors; JSON/GraphML/DOT export
- stylometry      : authorship attribution (Cosine Delta + Burrows's Delta)
- temporal        : timezone inference from activity-hour distributions
- llm             : optional Claude-backed claim extraction and finding review

Design stance
-------------
PASSIVE COLLECTION ONLY. The toolkit issues GET requests, reads what it is
served, and extracts identifiers. It never logs in, submits forms, performs
transactions, or acts on any misconfiguration it observes — an exposed endpoint
is noted and logged, never probed or exploited.

Analysis runs locally over what was collected. The few operations that reach the
network beyond the page fetch (TLS probing an http-only host, fetching a
favicon, verifying a clearnet certificate, Certificate Transparency lookups, and
Claude analysis) are each individually opt-in and named in the README.

Every inferred result carries its evidence and a confidence. Nothing this
toolkit produces is an attribution; it produces leads for an analyst.
"""

__version__ = "2.0.0"
