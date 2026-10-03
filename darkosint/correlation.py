"""Onion -> clearnet infrastructure correlation.

This is the de-anonymization step for *infrastructure*, as distinct from the
actor graph which de-anonymizes *people*. It consumes evidence already collected
(TLS certificates, response-header banners, favicon hashes, analytics IDs,
absolute URLs) and scores the hypothesis "this hidden service runs on, or is
operated alongside, this clearnet host".

Scoring
-------
Each method contributes an independent confidence. Where several methods point
at the same ``(onion_host, clearnet)`` pair the confidences are combined with
noisy-OR::

    combined = 1 - Π (1 - cᵢ)

so two weak-but-independent signals reinforce without ever reaching certainty,
and one strong signal is not diluted by weak ones. Every finding carries the
evidence that produced it, because an unexplained score is useless to an analyst
and inadmissible to anyone downstream.

Optional live verification
--------------------------
:meth:`CorrelationEngine.verify` takes a candidate clearnet domain, connects to
it *directly* (not over Tor — it is a public host being checked against public
data), and compares the certificate it presents with the one the hidden service
presented. An exact certificate or public-key match promotes the finding to the
highest confidence tier the toolkit issues. This is the only part of the module
that touches the network, and it is opt-in.

Everything remains passive: no port scanning, no request to any path, nothing
sent to the onion service beyond what was already fetched.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field

from .fingerprints import (
    ANALYTICS_ID,
    CLEARNET_DOMAIN,
    COOKIE_NAME,
    ETAG,
    FAVICON_HASH,
    GENERATOR,
    IPV4,
    POWERED_BY,
    S3_BUCKET,
    SERVER_BANNER,
    TLS_FINGERPRINT,
    TLS_SPKI,
)

logger = logging.getLogger("darkosint.correlation")

# ---------------------------------------------------------------------------
# method weights
# ---------------------------------------------------------------------------

#: Per-method base confidence. These are priors an analyst can and should tune;
#: they encode how uniquely each artifact class identifies one operator.
METHOD_WEIGHTS: dict[str, float] = {
    # Direct attribution: the hidden service's own certificate names a clearnet
    # host. Nothing else in passive collection is this strong.
    "tls_clearnet_name": 0.95,
    # Same certificate bytes served on both sides.
    "tls_cert_reuse": 0.92,
    # Same public key on both sides: survives certificate renewal, so it is
    # slightly stronger evidence of a shared machine than a shared cert.
    "tls_spki_reuse": 0.93,
    # Certificate names an IP directly.
    "tls_san_ip": 0.88,
    # Analytics/tag IDs are issued per operator account, not per site.
    "analytics_shared": 0.85,
    # An S3 bucket name is operator-controlled and globally unique.
    "s3_bucket_shared": 0.66,
    # Same favicon served from both: a deliberate branding choice, but favicons
    # are also copied between unrelated sites.
    "favicon_shared": 0.70,
    # Inode-style ETags encode filesystem state of a specific host.
    "etag_shared": 0.58,
    # A distinctive (non-stock) Server/X-Powered-By string.
    "banner_shared": 0.30,
    # A non-default cookie name shared by both stacks.
    "cookie_shared": 0.25,
    # The onion page simply references a clearnet domain. Weak on its own — this
    # is candidate generation, not attribution — but it compounds with others.
    "clearnet_reference": 0.20,
    # Live check: the clearnet host presents the same certificate/key.
    "verified_cert_match": 0.97,
    "verified_spki_match": 0.97,
    # Certificate Transparency logs name the onion's cert CN on a clearnet domain.
    "ct_log_match": 0.80,
}

#: Identifier types usable as a correlation key, and the method each implies.
_SHARED_KEY_METHODS: dict[str, str] = {
    TLS_FINGERPRINT: "tls_cert_reuse",
    TLS_SPKI: "tls_spki_reuse",
    ANALYTICS_ID: "analytics_shared",
    S3_BUCKET: "s3_bucket_shared",
    FAVICON_HASH: "favicon_shared",
    ETAG: "etag_shared",
    SERVER_BANNER: "banner_shared",
    POWERED_BY: "banner_shared",
    GENERATOR: "banner_shared",
    COOKIE_NAME: "cookie_shared",
}

_RE_DOMAINISH = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,252}\.[a-z]{2,24}$")

#: Default / self-signed certificate subject names that name no real clearnet
#: host. A stock ``localhost.localdomain`` cert is the out-of-the-box TLS config
#: of countless services; treating it as a leaked clearnet domain would fabricate
#: a 0.95 attribution out of a default that identifies nobody.
_DEFAULT_CERT_NAMES = {
    "localhost", "localhost.localdomain", "localdomain", "example.com",
    "example.org", "example.net", "invalid", "none", "default", "changeme",
    "test", "ubuntu", "debian", "server", "acme.com",
}


def is_onion(host: str) -> bool:
    return (host or "").lower().endswith(".onion")


def _is_default_cert_name(name: str) -> bool:
    """True for stock/self-signed names that attribute no real clearnet host."""
    n = (name or "").strip().lower().rstrip(".").lstrip("*.")
    return n in _DEFAULT_CERT_NAMES or n.endswith(".local") or n.endswith(".localdomain")


def combine(confidences: list[float]) -> float:
    """Noisy-OR combination of independent evidence."""
    product = 1.0
    for c in confidences:
        product *= (1.0 - max(0.0, min(1.0, c)))
    return round(1.0 - product, 4)


@dataclass
class Finding:
    """One scored onion -> clearnet hypothesis, with its supporting evidence."""

    onion_host: str
    clearnet: str
    confidence: float = 0.0
    methods: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)

    @property
    def indicator_type(self) -> str:
        return self.evidence[0].get("indicator_type", "") if self.evidence else ""

    @property
    def indicator_value(self) -> str:
        return self.evidence[0].get("indicator_value", "") if self.evidence else ""

    def explain(self) -> str:
        """A one-paragraph, analyst-readable justification for the score."""
        lines = [
            f"{self.onion_host}  ->  {self.clearnet}   "
            f"confidence {self.confidence:.2f}"
        ]
        for ev in self.evidence:
            lines.append(
                f"    [{ev['method']} {ev['weight']:.2f}] {ev['detail']}"
            )
        return "\n".join(lines)


class CorrelationEngine:
    """Derives clearnet attribution hypotheses from collected evidence."""

    def __init__(self, storage, config=None):
        self.storage = storage
        #: When present, live verification probes the candidate clearnet host
        #: *through Tor* instead of from the analyst's real IP.
        self.config = config

    # ---- evidence assembly ------------------------------------------------

    def _indicator_index(self) -> dict[tuple[str, str], dict[str, set[str]]]:
        """Map each correlation key to the onion and clearnet hosts carrying it.

        Result: ``{(type, value): {"onion": {hosts}, "clearnet": {hosts}}}``.
        """
        hosts = self.storage.source_hosts()
        index: dict[tuple[str, str], dict[str, set[str]]] = {}
        for source_id, rows in self.storage.identifiers_by_source().items():
            host = (hosts.get(source_id) or "").lower()
            if not host:
                continue
            side = "onion" if is_onion(host) else "clearnet"
            for row in rows:
                if row["type"] not in _SHARED_KEY_METHODS:
                    continue
                key = (row["type"], row["value"])
                index.setdefault(key, {"onion": set(), "clearnet": set()})[side].add(host)
        return index

    # ---- individual detectors ---------------------------------------------

    def _from_certificates(self) -> list[tuple[str, str, str, dict]]:
        """Clearnet names asserted by certificates served on onion hosts."""
        out: list[tuple[str, str, str, dict]] = []
        for cert in self.storage.certificates():
            host = (cert["host"] or "").lower()
            if not is_onion(host):
                continue
            names: list[str] = []
            if cert["subject_cn"]:
                names.append(cert["subject_cn"])
            try:
                names.extend(json.loads(cert["san_dns"] or "[]"))
            except (json.JSONDecodeError, TypeError):
                pass
            for name in names:
                n = (name or "").strip().lower().rstrip(".")
                if not n or n.endswith(".onion") or not _RE_DOMAINISH.match(n.lstrip("*.")):
                    continue
                if _is_default_cert_name(n):
                    continue
                out.append((
                    host, n, "tls_clearnet_name",
                    {
                        "indicator_type": "tls_cn/san",
                        "indicator_value": n,
                        "detail": (
                            f"TLS certificate served by {host} names {n!r} "
                            f"(issuer {cert['issuer_cn']!r}, serial {cert['serial']}, "
                            f"self-signed={bool(cert['self_signed'])})"
                        ),
                        "cert_sha256": cert["sha256"],
                        "spki_sha256": cert["spki_sha256"],
                    },
                ))
            try:
                for ip in json.loads(cert["san_ip"] or "[]"):
                    out.append((
                        host, ip, "tls_san_ip",
                        {
                            "indicator_type": IPV4,
                            "indicator_value": ip,
                            "detail": f"TLS certificate served by {host} names IP {ip}",
                            "cert_sha256": cert["sha256"],
                        },
                    ))
            except (json.JSONDecodeError, TypeError):
                pass
        return out

    def _from_shared_keys(self) -> list[tuple[str, str, str, dict]]:
        """Correlation keys observed on BOTH an onion host and a clearnet host."""
        out: list[tuple[str, str, str, dict]] = []
        for (type_, value), sides in self._indicator_index().items():
            if not sides["onion"] or not sides["clearnet"]:
                continue
            method = _SHARED_KEY_METHODS[type_]
            for onion_host in sides["onion"]:
                for clearnet in sides["clearnet"]:
                    out.append((
                        onion_host, clearnet, method,
                        {
                            "indicator_type": type_,
                            "indicator_value": value,
                            "detail": (
                                f"{type_} {value!r} observed on both {onion_host} "
                                f"and {clearnet}"
                            ),
                        },
                    ))
        return out

    def _from_references(self) -> list[tuple[str, str, str, dict]]:
        """Clearnet domains referenced from onion pages (candidate generation)."""
        out: list[tuple[str, str, str, dict]] = []
        hosts = self.storage.source_hosts()
        for source_id, rows in self.storage.identifiers_by_source().items():
            host = (hosts.get(source_id) or "").lower()
            if not is_onion(host):
                continue
            for row in rows:
                if row["type"] != CLEARNET_DOMAIN:
                    continue
                domain = row["value"].lower()
                if domain.endswith(".onion"):
                    continue
                # A cert-sourced clearnet name is handled by _from_certificates
                # at far higher confidence; do not double-count it here.
                if "CERTIFICATE" in (row["context"] or "").upper():
                    continue
                out.append((
                    host, domain, "clearnet_reference",
                    {
                        "indicator_type": CLEARNET_DOMAIN,
                        "indicator_value": domain,
                        "detail": f"{host} references clearnet domain {domain} "
                                  f"({row['context'] or 'in page markup'})",
                    },
                ))
        return out

    # ---- orchestration ----------------------------------------------------

    def run(self, persist: bool = True, min_confidence: float = 0.0) -> list[Finding]:
        """Score every onion -> clearnet hypothesis the evidence supports."""
        raw: list[tuple[str, str, str, dict]] = []
        raw.extend(self._from_certificates())
        raw.extend(self._from_shared_keys())
        raw.extend(self._from_references())

        merged: dict[tuple[str, str], Finding] = {}
        for onion_host, clearnet, method, evidence in raw:
            if not onion_host or not clearnet or onion_host == clearnet:
                continue
            key = (onion_host, clearnet)
            finding = merged.setdefault(key, Finding(onion_host=onion_host, clearnet=clearnet))
            weight = METHOD_WEIGHTS.get(method, 0.1)
            # One method contributes once per pair, however many artifacts
            # triggered it — otherwise three shared cookies would look like
            # three independent proofs.
            if method in finding.methods:
                continue
            finding.methods.append(method)
            finding.evidence.append({**evidence, "method": method, "weight": weight})

        findings: list[Finding] = []
        for finding in merged.values():
            finding.confidence = combine([e["weight"] for e in finding.evidence])
            if finding.confidence >= min_confidence:
                findings.append(finding)

        findings.sort(key=lambda f: (-f.confidence, f.onion_host, f.clearnet))

        if persist:
            # Recompute wholesale: correlation is deterministic from the current
            # evidence, so old rows are cleared rather than left to accumulate
            # (and to double-count when a pair gains a new method next run).
            self.storage.clear_correlations()
            for f in findings:
                self.storage.add_correlation(
                    onion_host=f.onion_host,
                    indicator_type=f.indicator_type or "composite",
                    indicator_value=f.indicator_value or ",".join(f.methods),
                    clearnet=f.clearnet,
                    method="+".join(f.methods),
                    confidence=f.confidence,
                    evidence={"evidence": f.evidence},
                )
        logger.info(
            "Correlation pass: %d finding(s) from %d raw signal(s)", len(findings), len(raw)
        )
        return findings

    # ---- optional live verification ---------------------------------------

    def verify(self, finding: Finding, timeout: float = 20.0, direct: bool = False) -> Finding:
        """Connect to the candidate clearnet host and compare its certificate.

        Promotes the finding when the clearnet host presents the same certificate
        or the same public key as the hidden service did. Network-dependent and
        opt-in; failure leaves the finding untouched.

        By default the probe goes **through Tor** (when a config is available), so
        checking a suspected operator's clearnet host does not reveal the
        analyst's real IP to that host moments after crawling its onion service.
        Pass ``direct=True`` to connect from the local IP instead.
        """
        onion_certs = [
            c for c in self.storage.certificates()
            if (c["host"] or "").lower() == finding.onion_host
        ]
        if not onion_certs:
            return finding

        if self.config is not None and not direct:
            from .tls_probe import probe
            observation = probe(
                self.config, finding.clearnet, 443, server_hostname=finding.clearnet
            )
        else:
            from .tls_probe import direct_probe
            observation = direct_probe(finding.clearnet, timeout=timeout)
        if not observation.ok or observation.certificate is None:
            logger.debug(
                "Verification probe of %s failed: %s", finding.clearnet, observation.error
            )
            return finding

        clear = observation.certificate
        for oc in onion_certs:
            method = detail = None
            if oc["sha256"] and oc["sha256"] == clear.sha256:
                method = "verified_cert_match"
                detail = (
                    f"{finding.clearnet} presents the byte-identical certificate "
                    f"(SHA-256 {clear.sha256}) served by {finding.onion_host}"
                )
            elif oc["spki_sha256"] and oc["spki_sha256"] == clear.spki_sha256:
                method = "verified_spki_match"
                detail = (
                    f"{finding.clearnet} presents the same TLS public key "
                    f"(SPKI SHA-256 {clear.spki_sha256}) as {finding.onion_host}"
                )
            if method and method not in finding.methods:
                finding.methods.append(method)
                finding.evidence.append({
                    "method": method,
                    "weight": METHOD_WEIGHTS[method],
                    "indicator_type": TLS_SPKI if "spki" in method else TLS_FINGERPRINT,
                    "indicator_value": clear.spki_sha256 if "spki" in method else clear.sha256,
                    "detail": detail,
                })
                logger.warning("VERIFIED: %s", detail)

        finding.confidence = combine([e["weight"] for e in finding.evidence])
        return finding

    def enrich_from_ct(self, finding: Finding, timeout: float = 25.0) -> Finding:
        """Look the onion service's certificate CN up in Certificate Transparency.

        CT logs are public, clearnet, and free to query, so this adds no exposure
        on the Tor side. A CN that a hidden service serves and that also appears
        in a CT-logged certificate for a clearnet domain is a strong link.
        """
        try:
            import requests
        except ImportError:
            logger.warning("requests not installed; skipping CT enrichment")
            return finding

        cns = {
            (c["subject_cn"] or "").strip()
            for c in self.storage.certificates()
            if (c["host"] or "").lower() == finding.onion_host and c["subject_cn"]
        }
        for cn in cns:
            if not cn or cn.endswith(".onion"):
                continue
            try:
                resp = requests.get(
                    "https://crt.sh/",
                    params={"q": cn, "output": "json"},
                    timeout=timeout,
                )
                rows = resp.json() if resp.ok else []
            except Exception as exc:  # noqa: BLE001 - enrichment is best-effort
                logger.debug("crt.sh lookup for %r failed: %s", cn, exc)
                continue
            names = {
                n.strip().lower()
                for row in rows or []
                for n in str(row.get("name_value", "")).splitlines()
                if n.strip() and not n.strip().endswith(".onion")
            }
            if finding.clearnet in names and "ct_log_match" not in finding.methods:
                finding.methods.append("ct_log_match")
                finding.evidence.append({
                    "method": "ct_log_match",
                    "weight": METHOD_WEIGHTS["ct_log_match"],
                    "indicator_type": "ct_log",
                    "indicator_value": cn,
                    "detail": (
                        f"Certificate Transparency logs link CN {cn!r} "
                        f"(served by {finding.onion_host}) to {finding.clearnet}"
                    ),
                })
                finding.confidence = combine([e["weight"] for e in finding.evidence])
        return finding
