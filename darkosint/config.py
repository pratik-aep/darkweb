"""Layered configuration.

Precedence (lowest to highest): built-in defaults -> config.ini -> CLI overrides.

Keeping config in a small, typed dataclass (rather than passing a dict around)
means every consumer gets validated, documented fields and sensible defaults
even when no config file is present.
"""
from __future__ import annotations

import configparser
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class TorConfig:
    socks_host: str = "127.0.0.1"
    socks_port: int = 9050
    control_port: int = 9051
    control_password: str = ""
    rotate_every: int = 25  # request a new circuit every N requests (0 = never)

    @property
    def proxy_url(self) -> str:
        # socks5h:// -> resolve hostnames (incl. .onion) through Tor, not locally.
        return f"socks5h://{self.socks_host}:{self.socks_port}"


@dataclass(frozen=True)
class HttpConfig:
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0"
    )
    timeout: float = 60.0
    max_retries: int = 4
    backoff_base: float = 2.0
    backoff_cap: float = 60.0
    per_host_delay: float = 5.0
    max_bytes: int = 5 * 1024 * 1024


@dataclass(frozen=True)
class CrawlConfig:
    max_pages: int = 100
    max_depth: int = 2
    expand_frontier: bool = True
    stay_on_seed_hosts: bool = False


@dataclass(frozen=True)
class EvidenceConfig:
    """Which optional evidence classes the collector gathers.

    Each of these costs an extra connection or request beyond the page fetch the
    analyst asked for, so each is individually switchable and the two that reach
    somewhere the page fetch did not go are OFF by default.
    """

    #: Capture the TLS certificate for pages already fetched over https://.
    #: No extra contact — the handshake happened anyway.
    capture_tls: bool = True

    #: Also open port 443 on hosts only ever fetched over http://. This IS a new
    #: connection the operator did not serve us, so it is opt-in.
    probe_tls_on_http: bool = False

    #: Fetch the favicon (the <link rel=icon> target, else /favicon.ico) to
    #: compute the Shodan-compatible hash. One extra GET per host.
    fetch_favicon: bool = False

    #: Store page text as documents, feeding stylometry and temporal analysis.
    store_documents: bool = True

    #: Run the clearnet correlation pass automatically at the end of a crawl.
    correlate_after_crawl: bool = True


@dataclass(frozen=True)
class Config:
    tor: TorConfig = field(default_factory=TorConfig)
    http: HttpConfig = field(default_factory=HttpConfig)
    crawl: CrawlConfig = field(default_factory=CrawlConfig)
    evidence: EvidenceConfig = field(default_factory=EvidenceConfig)

    # ---- construction -----------------------------------------------------

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        """Build a Config from defaults, overlaying an INI file if given/present."""
        cfg = cls()
        if path is None:
            return cfg
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {p}")

        parser = configparser.ConfigParser()
        parser.read(p)

        tor = replace(
            cfg.tor,
            socks_host=parser.get("tor", "socks_host", fallback=cfg.tor.socks_host),
            socks_port=parser.getint("tor", "socks_port", fallback=cfg.tor.socks_port),
            control_port=parser.getint(
                "tor", "control_port", fallback=cfg.tor.control_port
            ),
            control_password=parser.get(
                "tor", "control_password", fallback=cfg.tor.control_password
            ),
            rotate_every=parser.getint(
                "tor", "rotate_every", fallback=cfg.tor.rotate_every
            ),
        )
        http = replace(
            cfg.http,
            user_agent=parser.get("http", "user_agent", fallback=cfg.http.user_agent),
            timeout=parser.getfloat("http", "timeout", fallback=cfg.http.timeout),
            max_retries=parser.getint(
                "http", "max_retries", fallback=cfg.http.max_retries
            ),
            backoff_base=parser.getfloat(
                "http", "backoff_base", fallback=cfg.http.backoff_base
            ),
            backoff_cap=parser.getfloat(
                "http", "backoff_cap", fallback=cfg.http.backoff_cap
            ),
            per_host_delay=parser.getfloat(
                "http", "per_host_delay", fallback=cfg.http.per_host_delay
            ),
            max_bytes=parser.getint("http", "max_bytes", fallback=cfg.http.max_bytes),
        )
        crawl = replace(
            cfg.crawl,
            max_pages=parser.getint(
                "crawl", "max_pages", fallback=cfg.crawl.max_pages
            ),
            max_depth=parser.getint("crawl", "max_depth", fallback=cfg.crawl.max_depth),
            expand_frontier=parser.getboolean(
                "crawl", "expand_frontier", fallback=cfg.crawl.expand_frontier
            ),
            stay_on_seed_hosts=parser.getboolean(
                "crawl", "stay_on_seed_hosts", fallback=cfg.crawl.stay_on_seed_hosts
            ),
        )
        evidence = replace(
            cfg.evidence,
            capture_tls=parser.getboolean(
                "evidence", "capture_tls", fallback=cfg.evidence.capture_tls
            ),
            probe_tls_on_http=parser.getboolean(
                "evidence", "probe_tls_on_http", fallback=cfg.evidence.probe_tls_on_http
            ),
            fetch_favicon=parser.getboolean(
                "evidence", "fetch_favicon", fallback=cfg.evidence.fetch_favicon
            ),
            store_documents=parser.getboolean(
                "evidence", "store_documents", fallback=cfg.evidence.store_documents
            ),
            correlate_after_crawl=parser.getboolean(
                "evidence", "correlate_after_crawl",
                fallback=cfg.evidence.correlate_after_crawl,
            ),
        )
        return cls(tor=tor, http=http, crawl=crawl, evidence=evidence)

    def with_overrides(self, **overrides: Any) -> "Config":
        """Return a copy with non-None CLI overrides applied.

        Keys use dotted notation, e.g. with_overrides(**{"crawl.max_pages": 10}).
        None values are ignored so "flag not supplied" never clobbers a config value.
        """
        tor_kw: dict[str, Any] = {}
        http_kw: dict[str, Any] = {}
        crawl_kw: dict[str, Any] = {}
        evidence_kw: dict[str, Any] = {}
        buckets = {
            "tor": tor_kw, "http": http_kw,
            "crawl": crawl_kw, "evidence": evidence_kw,
        }
        for dotted, value in overrides.items():
            if value is None:
                continue
            section, _, key = dotted.partition(".")
            if section not in buckets:
                raise KeyError(f"Unknown config override section: {dotted}")
            buckets[section][key] = value
        return Config(
            tor=replace(self.tor, **tor_kw) if tor_kw else self.tor,
            http=replace(self.http, **http_kw) if http_kw else self.http,
            crawl=replace(self.crawl, **crawl_kw) if crawl_kw else self.crawl,
            evidence=(
                replace(self.evidence, **evidence_kw) if evidence_kw else self.evidence
            ),
        )


def load_seeds(path: str | Path) -> list[str]:
    """Read seed URLs, ignoring blank lines and '#' comments."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Seeds file not found: {p}")
    seeds: list[str] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        seeds.append(line)
    return seeds
