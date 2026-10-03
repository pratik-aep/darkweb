"""Audit logging.

Everything the collector does (requests, statuses, retries, circuit rotations,
snapshots written, identifiers found, exposure notes) is logged to both the
console and a rotating file under the output directory, so a run is reproducible
and reviewable after the fact.
"""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

_CONFIGURED = False


def setup_logging(output_dir: str | Path, verbose: bool = False) -> logging.Logger:
    """Configure the 'darkosint' logger tree once; return the package logger."""
    global _CONFIGURED
    logger = logging.getLogger("darkosint")

    if _CONFIGURED:
        return logger

    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(fmt)
    logger.addHandler(console)

    log_dir = Path(output_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    # 5 MB x 5 files keeps a bounded but useful audit trail.
    file_handler = RotatingFileHandler(
        log_dir / "audit.log", maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)  # the file always keeps full detail
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    _CONFIGURED = True
    logger.debug("Logging initialised (audit log at %s)", log_dir / "audit.log")
    return logger
