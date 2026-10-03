"""Activity-time analysis and timezone inference.

People sleep. A threat actor can rotate every handle, key and wallet they own
and still post on a schedule dictated by the sun where they physically are, and
that schedule survives across marketplaces because it is not a credential they
can change. Recovering an approximate UTC offset narrows "somewhere on Earth" to
a band of longitudes, and — more usefully — two handles whose activity curves
align are a corroborating signal for the actor graph.

Method
------
1. Parse timestamps out of collected page text (:func:`extract_timestamps`).
2. Bin them into a 24-bin histogram of UTC hours.
3. Cross-correlate that histogram, at all 27 candidate offsets from UTC-12 to
   UTC+14, against a reference human diurnal curve.
4. Report the best-fitting offset with a confidence derived from how much better
   it fits than the runner-up — a flat, featureless histogram yields low
   confidence, as it should.

Caveats, stated plainly: site-rendered timestamps are frequently already
localized to the *viewer* or to the server's timezone rather than the poster's,
scheduled posts and bots break the assumption entirely, and shift workers exist.
This produces a lead, not a location.
"""
from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger("darkosint.temporal")

#: Reference diurnal activity curve, indexed by LOCAL hour 0..23. Low overnight,
#: ramping through the morning, sustained afternoon, evening peak. Only its
#: *shape* matters — it is correlated against, never subtracted.
REFERENCE_CURVE = [
    0.15, 0.08, 0.05, 0.04, 0.04, 0.06,   # 00-05 asleep
    0.12, 0.28, 0.45, 0.62, 0.72, 0.78,   # 06-11 morning
    0.80, 0.82, 0.85, 0.86, 0.88, 0.90,   # 12-17 afternoon
    0.95, 1.00, 0.98, 0.85, 0.60, 0.32,   # 18-23 evening peak, winding down
]

_MONTHS = {
    m: i for i, m in enumerate(
        ["jan", "feb", "mar", "apr", "may", "jun",
         "jul", "aug", "sep", "oct", "nov", "dec"], start=1
    )
}

# Timestamp shapes common on forums and marketplaces.
_RE_ISO = re.compile(
    r"\b(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?\b"
)
_RE_DMY = re.compile(
    r"\b(\d{1,2})[/.-](\d{1,2})[/.-](\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\b"
)
_RE_MONTH_NAME = re.compile(
    r"\b(\d{1,2})\s+([A-Za-z]{3,9})\s+(\d{4})(?:\s+(?:at\s+)?(\d{1,2}):(\d{2}))?\b"
)
_RE_NAME_MONTH = re.compile(
    r"\b([A-Za-z]{3,9})\s+(\d{1,2}),?\s+(\d{4})(?:\s+(?:at\s+)?(\d{1,2}):(\d{2}))?\b"
)
_RE_RELATIVE = re.compile(
    r"\b(\d{1,3})\s+(minute|min|hour|hr|day)s?\s+ago\b", re.IGNORECASE
)


@dataclass
class TimeProfile:
    """One subject's activity distribution over UTC hours."""

    subject: str
    hours: Counter = field(default_factory=Counter)
    samples: int = 0

    def histogram(self) -> list[float]:
        """Normalized 24-bin histogram of UTC hours."""
        total = sum(self.hours.values())
        if not total:
            return [0.0] * 24
        return [self.hours.get(h, 0) / total for h in range(24)]


@dataclass
class TimezoneEstimate:
    subject: str
    utc_offset: int | None
    confidence: float
    samples: int
    histogram: list[float] = field(default_factory=list)
    quiet_hours_utc: tuple[int, int] | None = None
    note: str = ""

    def explain(self) -> str:
        if self.utc_offset is None:
            return f"{self.subject}: insufficient data ({self.samples} timestamp(s))"
        sign = "+" if self.utc_offset >= 0 else "-"
        quiet = (
            f", quiet {self.quiet_hours_utc[0]:02d}:00-{self.quiet_hours_utc[1]:02d}:00 UTC"
            if self.quiet_hours_utc else ""
        )
        return (
            f"{self.subject}: likely UTC{sign}{abs(self.utc_offset)} "
            f"(confidence {self.confidence:.2f}, {self.samples} timestamps{quiet})"
            + (f" — {self.note}" if self.note else "")
        )


def extract_timestamps(text: str, reference: datetime | None = None) -> list[datetime]:
    """Parse timestamps out of page text.

    Relative stamps ("3 hours ago") are resolved against ``reference``, which
    should be the time the page was collected; without one they are skipped,
    because an unanchored relative time carries no hour information.
    """
    out: list[datetime] = []
    if not text:
        return out

    def _add(y, mo, d, h, mi, s=0):
        try:
            out.append(datetime(int(y), int(mo), int(d), int(h), int(mi), int(s)))
        except (ValueError, TypeError):
            pass

    for m in _RE_ISO.finditer(text):
        _add(m.group(1), m.group(2), m.group(3), m.group(4), m.group(5), m.group(6) or 0)
    for m in _RE_DMY.finditer(text):
        # Ambiguous D/M vs M/D: treat >12 as the day, else assume D/M (the
        # dominant convention outside the US, and most onion forums are not US).
        a, b = int(m.group(1)), int(m.group(2))
        day, month = (a, b) if a > 12 or b <= 12 else (b, a)
        _add(m.group(3), month, day, m.group(4), m.group(5), m.group(6) or 0)
    for m in _RE_MONTH_NAME.finditer(text):
        month = _MONTHS.get(m.group(2)[:3].lower())
        if month and m.group(4) is not None:
            _add(m.group(3), month, m.group(1), m.group(4), m.group(5))
    for m in _RE_NAME_MONTH.finditer(text):
        month = _MONTHS.get(m.group(1)[:3].lower())
        if month and m.group(4) is not None:
            _add(m.group(3), month, m.group(2), m.group(4), m.group(5))

    if reference is not None:
        from datetime import timedelta
        for m in _RE_RELATIVE.finditer(text):
            n, unit = int(m.group(1)), m.group(2).lower()
            delta = (
                timedelta(minutes=n) if unit.startswith("min")
                else timedelta(hours=n) if unit.startswith("h")
                else timedelta(days=n)
            )
            out.append(reference - delta)
    return out


def _pearson(a: list[float], b: list[float]) -> float:
    n = len(a)
    if n == 0 or n != len(b):
        return 0.0
    ma, mb = sum(a) / n, sum(b) / n
    num = sum((x - ma) * (y - mb) for x, y in zip(a, b))
    da = math.sqrt(sum((x - ma) ** 2 for x in a))
    db = math.sqrt(sum((y - mb) ** 2 for y in b))
    if da == 0 or db == 0:
        return 0.0
    return num / (da * db)


def quiet_window(histogram: list[float], width: int = 6) -> tuple[int, int]:
    """The ``width``-hour circular window with the least activity."""
    best_start, best_total = 0, float("inf")
    for start in range(24):
        total = sum(histogram[(start + k) % 24] for k in range(width))
        if total < best_total:
            best_start, best_total = start, total
    return best_start, (best_start + width) % 24


def infer_timezone(profile: TimeProfile, min_samples: int = 8) -> TimezoneEstimate:
    """Estimate a UTC offset by fitting the activity curve.

    For a candidate offset ``o``, UTC hour ``h`` is local hour ``h + o``; the
    histogram is rotated accordingly and correlated against the reference curve.
    """
    histogram = profile.histogram()
    samples = sum(profile.hours.values())
    if samples < min_samples:
        return TimezoneEstimate(
            subject=profile.subject, utc_offset=None, confidence=0.0,
            samples=samples, histogram=histogram,
            note=f"need >= {min_samples} timestamps to fit a curve",
        )

    scores: list[tuple[float, int]] = []
    for offset in range(-12, 15):
        rotated = [histogram[(h - offset) % 24] for h in range(24)]
        scores.append((_pearson(rotated, REFERENCE_CURVE), offset))
    scores.sort(reverse=True)

    best_r, best_offset = scores[0]
    runner_up = scores[1][0] if len(scores) > 1 else 0.0

    # Confidence blends absolute fit with how decisively it beat the alternative:
    # a histogram that fits every offset equally well tells us nothing.
    margin = max(0.0, best_r - runner_up)
    confidence = max(0.0, min(0.95, (max(0.0, best_r) * 0.7) + (margin * 3.0)))
    # Thin evidence should never produce a confident answer.
    confidence *= min(1.0, samples / 40.0)

    return TimezoneEstimate(
        subject=profile.subject,
        utc_offset=best_offset,
        confidence=round(confidence, 3),
        samples=samples,
        histogram=histogram,
        quiet_hours_utc=quiet_window(histogram),
        note=f"curve fit r={best_r:.3f}",
    )


class TemporalAnalyzer:
    """Builds activity profiles from stored documents and infers offsets."""

    def __init__(self, storage):
        self.storage = storage

    def profiles(self) -> dict[str, TimeProfile]:
        """One activity profile per handle, from parsed and stored timestamps."""
        out: dict[str, TimeProfile] = {}
        for row in self.storage.documents(with_handle=True):
            handle = (row["handle"] or "").strip()
            if not handle:
                continue
            profile = out.setdefault(handle, TimeProfile(subject=handle))

            stamps: list[datetime] = []
            if row["posted_at"]:
                try:
                    stamps.append(datetime.fromisoformat(row["posted_at"]))
                except (ValueError, TypeError):
                    pass
            if not stamps:
                stamps = extract_timestamps(row["text"] or "")
            for ts in stamps:
                profile.hours[ts.hour] += 1
                profile.samples += 1
        return out

    def run(self, min_samples: int = 8) -> list[TimezoneEstimate]:
        """Estimate a timezone for every handle with enough timestamps."""
        estimates = [
            infer_timezone(p, min_samples=min_samples)
            for p in self.profiles().values()
        ]
        estimates.sort(key=lambda e: -e.confidence)
        logger.info(
            "Temporal analysis: %d handle(s) profiled, %d with a usable estimate",
            len(estimates), sum(1 for e in estimates if e.utc_offset is not None),
        )
        return estimates

    def activity_similarity(self, a: str, b: str) -> float:
        """Correlation between two handles' activity curves, rescaled to 0..1."""
        profiles = self.profiles()
        if a not in profiles or b not in profiles:
            return 0.0
        return (_pearson(profiles[a].histogram(), profiles[b].histogram()) + 1.0) / 2.0
