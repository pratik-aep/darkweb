"""Stylometric authorship attribution.

The question this answers: *handle A posts on one marketplace and handle B posts
on another — are they the same person?* When an actor is careful enough to use a
fresh handle, a fresh key and a fresh wallet on every market, writing style is
often the only artifact they forget to rotate.

Four complementary feature families are computed, deliberately measuring
different things so that agreement between them means something:

``char_ngram``
    TF-IDF weighted character 3- and 4-grams, compared by cosine similarity.
    Captures spelling habits, morphology and typos below the word level, and is
    robust to topic change — the standard workhorse of authorship attribution.
``function_words``
    Relative frequencies of closed-class words ("the", "of", "actually"). These
    are chosen unconsciously and are almost independent of subject matter.
``structural``
    Sentence and word length, punctuation and capitalisation rates, digit and
    emoji use, leetspeak — the typographic signature.
``burrows_delta``
    Burrows's Delta over the most frequent words: the classic, peer-reviewed
    attribution statistic, included because it is the one a reviewer will ask
    for by name.

Measured performance
--------------------
Against 5 known authors split into 3 disjoint samples each (15 profiles, 105
pairs, 15 of them true same-author pairs):

===================  ==========  ==========  =========  =========
sample size          rule        precision   recall     F1
===================  ==========  ==========  =========  =========
12,000 chars         score≥0.56  0.92        0.80       0.857
12,000 chars         ≥2.5σ       1.00        0.47       0.636
2,000 chars          score≥0.56  1.00        0.47       0.636
2,000 chars          ≥2.5σ       1.00        0.47       0.636
===================  ==========  ==========  =========  =========

Read honestly: this finds most same-author pairs on reasonable samples and
rarely accuses the wrong pair, but it misses pairs, and it misses more of them
as samples shorten. The σ rule never produced a false positive in testing but
recovers fewer pairs; :attr:`Comparison.is_lead` accepts either, which in
measurement matched the better of the two at both sample sizes.

Scores are *similarities, not identities*. Two people writing in the same
register score highly; the output is a ranked lead list for an analyst, and the
graph layer deliberately caps how much an edge built from style alone can
contribute. Implemented on the standard library only, so it runs anywhere the
collector does.
"""
from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field

logger = logging.getLogger("darkosint.stylometry")

#: Below this many characters a profile is statistically meaningless.
MIN_CHARS = 200
#: Below this, a score is reported but flagged as low-confidence.
RELIABLE_CHARS = 600

#: Score at or above which a pair is worth an analyst's attention, and the point
#: at which :mod:`darkosint.graph` will draw a stylometric edge.
#:
#: Calibrated, not guessed. Measured on 5 known authors x 3 disjoint 12,000-char
#: samples (15 profiles, 105 pairs, 15 of them true same-author pairs):
#:
#:     same-author   min 0.472  mean 0.602  max 0.709
#:     cross-author  min 0.333  mean 0.443  max 0.585
#:     best F1 0.857 at 0.559  (12 true positives, 1 false positive, 3 missed)
#:
#: The distributions overlap, which is the honest result for samples this short:
#: a score above the threshold is a *lead*, never a conclusion, and the graph
#: layer caps how much a style-only edge can contribute accordingly.
#:
#: **Absolute scores depend on sample length and corpus size.** Standardization
#: is against the corpus, so with few profiles or short texts the whole score
#: distribution compresses toward the middle — measured same-author pairs at
#: ~1,200 characters land near 0.39 rather than 0.60, while still ranking above
#: every cross-author pair. Read the *ranking* first and the absolute value
#: second, and treat this constant as tuned for samples of several thousand
#: characters across a reasonable number of candidate handles. Because of that
#: drift, :attr:`Comparison.is_lead` also accepts a pair that stands out from
#: the rest of its own run, which is scale-free — see :func:`standout_scores`.
STYLOMETRY_MIN_SCORE = 0.56

#: Robust standard deviations above the run's median at which a pair is treated
#: as standing apart from the field, regardless of its absolute score.
STANDOUT_SIGMA = 2.5

# Closed-class words: chosen unconsciously, largely topic-independent.
FUNCTION_WORDS = (
    "a about above after again against all am an and any are aren't as at be "
    "because been before being below between both but by can cannot could "
    "couldn't did didn't do does doesn't doing don't down during each few for "
    "from further had hadn't has hasn't have haven't having he her here hers "
    "herself him himself his how however i if in into is isn't it its itself "
    "just me more most must my myself no nor not of off on once only or other "
    "ought our ours ourselves out over own same shan't she should shouldn't so "
    "some such than that the their theirs them themselves then there these "
    "they this those through to too under until up very was wasn't we were "
    "weren't what when where which while who whom why with won't would "
    "wouldn't you your yours yourself yourselves actually basically literally "
    "obviously perhaps maybe really quite rather simply therefore thus indeed"
).split()

_RE_WORD = re.compile(r"[a-z']+")
_RE_SENTENCE = re.compile(r"[.!?]+[\s$]")
_RE_EMOJI = re.compile(
    "[\U0001F300-\U0001FAFF\U00002600-\U000027BF\U0001F900-\U0001F9FF]"
)
_RE_LEET = re.compile(r"\b\w*[0-9]+\w*[a-z]\w*\b|\b[a-z]+[0-9]+\b", re.IGNORECASE)
_RE_WS = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Collapse whitespace; keep case and punctuation, which are both signal."""
    return _RE_WS.sub(" ", (text or "")).strip()


# ---------------------------------------------------------------------------
# profiles
# ---------------------------------------------------------------------------


@dataclass
class Profile:
    """The stylometric fingerprint of one author's combined text."""

    handle: str
    length: int = 0
    doc_count: int = 0
    char_ngrams: Counter = field(default_factory=Counter)
    word_freqs: Counter = field(default_factory=Counter)
    function_freqs: dict[str, float] = field(default_factory=dict)
    structural: dict[str, float] = field(default_factory=dict)
    total_words: int = 0

    @property
    def reliable(self) -> bool:
        return self.length >= RELIABLE_CHARS

    @property
    def usable(self) -> bool:
        return self.length >= MIN_CHARS


def _structural_features(text: str, words: list[str]) -> dict[str, float]:
    """Typographic habits, every one expressed as a length-invariant rate.

    Deliberately excluded: type/token ratio and hapax legomena rate. Both are
    standard lexical-richness measures and both fall monotonically as a sample
    grows — a mathematical property of the measures, not of the writer. Included
    here they would encode *how much text was collected about someone* into
    their fingerprint, and the comparison would start matching authors by corpus
    size. Word-level lexical choice is already captured by the Delta channel,
    which is standardized against the corpus and does not have this defect.
    """
    n = max(1, len(text))
    nw = max(1, len(words))
    sentences = [s for s in _RE_SENTENCE.split(text) if s.strip()]
    letters = sum(1 for c in text if c.isalpha())
    uppers = sum(1 for c in text if c.isupper())
    return {
        "avg_word_len": sum(len(w) for w in words) / nw,
        "avg_sentence_len": (nw / len(sentences)) if sentences else float(nw),
        "upper_rate": uppers / max(1, letters),
        "digit_rate": sum(c.isdigit() for c in text) / n,
        "space_rate": text.count(" ") / n,
        "comma_rate": text.count(",") / n,
        "period_rate": text.count(".") / n,
        "exclaim_rate": text.count("!") / n,
        "question_rate": text.count("?") / n,
        "ellipsis_rate": text.count("...") / n,
        "dash_rate": (text.count("-") + text.count("—")) / n,
        "apostrophe_rate": (text.count("'") + text.count("’")) / n,
        "paren_rate": text.count("(") / n,
        "emoji_rate": len(_RE_EMOJI.findall(text)) / n,
        "leet_rate": len(_RE_LEET.findall(text)) / nw,
    }


def build_profile(handle: str, texts: list[str], ngram_sizes=(3, 4)) -> Profile:
    """Build a :class:`Profile` from every text attributed to one handle."""
    joined = normalize(" \n ".join(t for t in texts if t))
    lowered = joined.lower()
    words = _RE_WORD.findall(lowered)

    ngrams: Counter = Counter()
    for size in ngram_sizes:
        if len(lowered) >= size:
            ngrams.update(lowered[i:i + size] for i in range(len(lowered) - size + 1))

    word_freqs = Counter(words)
    total_words = max(1, len(words))
    function_freqs = {
        w: word_freqs.get(w, 0) / total_words for w in FUNCTION_WORDS
    }

    return Profile(
        handle=handle,
        length=len(joined),
        doc_count=len([t for t in texts if t]),
        char_ngrams=ngrams,
        word_freqs=word_freqs,
        function_freqs=function_freqs,
        structural=_structural_features(joined, words),
        total_words=total_words,
    )


# ---------------------------------------------------------------------------
# similarity measures
# ---------------------------------------------------------------------------
#
# Why not plain cosine on TF-IDF: measured against two known authors it does not
# work. Raw n-gram cosine between two different authors writing English lands
# around 0.84, and between two samples by the *same* author around 0.87 — the
# signal is swamped by the shared language, and the bands overlap.
#
# The fix is the one the authorship-attribution literature settled on: standardize
# every feature dimension across the corpus *before* comparing, so each feature
# contributes how far each author deviates from the norm rather than how common
# the feature is in the language. Applying that to Burrows's Delta and then
# taking the cosine gives "Cosine Delta" (Smith & Aldridge 2011), which measurably
# outperforms classic Delta. That is the primary measure here; classic Delta is
# retained and reported alongside it as a cross-check.


@dataclass
class CorpusModel:
    """Fixed feature space plus per-dimension corpus mean and standard deviation.

    Standardization is what makes the comparison about the *author* rather than
    about the language, so the model must be built from the whole candidate set
    and shared by every pairwise comparison.
    """

    vocabulary: list[str] = field(default_factory=list)
    ngrams: list[str] = field(default_factory=list)
    structural_keys: list[str] = field(default_factory=list)
    mean: dict[str, float] = field(default_factory=dict)
    sd: dict[str, float] = field(default_factory=dict)

    @property
    def dimensions(self) -> int:
        return len(self.mean)


def _raw_features(
    profile: Profile, vocabulary: list[str], ngrams: list[str], structural_keys: list[str]
) -> dict[str, float]:
    """Relative-frequency feature vector over a fixed feature space."""
    out: dict[str, float] = {}
    total_words = max(1, profile.total_words)
    for word in vocabulary:
        out[f"w:{word}"] = profile.word_freqs.get(word, 0) / total_words
    total_ngrams = max(1, sum(profile.char_ngrams.values()))
    for gram in ngrams:
        out[f"g:{gram}"] = profile.char_ngrams.get(gram, 0) / total_ngrams
    for key in structural_keys:
        out[f"s:{key}"] = profile.structural.get(key, 0.0)
    return out


def build_corpus_model(
    profiles: list[Profile], top_words: int = 250, top_ngrams: int = 1500
) -> CorpusModel:
    """Fit the shared feature space and its per-dimension statistics."""
    word_counts: Counter = Counter()
    gram_counts: Counter = Counter()
    for p in profiles:
        word_counts.update(p.word_freqs)
        gram_counts.update(p.char_ngrams)

    vocabulary = [w for w, _ in word_counts.most_common(top_words)]
    # Keep function words in the space even if they missed the frequency cut.
    for w in FUNCTION_WORDS:
        if w in word_counts and w not in vocabulary:
            vocabulary.append(w)
    ngrams = [g for g, _ in gram_counts.most_common(top_ngrams)]
    structural_keys = sorted(profiles[0].structural) if profiles else []

    model = CorpusModel(
        vocabulary=vocabulary, ngrams=ngrams, structural_keys=structural_keys
    )
    vectors = [
        _raw_features(p, vocabulary, ngrams, structural_keys) for p in profiles
    ]
    n = max(1, len(vectors))
    for key in (vectors[0] if vectors else {}):
        series = [v.get(key, 0.0) for v in vectors]
        mean = sum(series) / n
        var = sum((x - mean) ** 2 for x in series) / n
        model.mean[key] = mean
        model.sd[key] = math.sqrt(var)
    return model


def standardize(profile: Profile, model: CorpusModel) -> dict[str, float]:
    """Z-score a profile against the corpus: the Delta transformation."""
    raw = _raw_features(profile, model.vocabulary, model.ngrams, model.structural_keys)
    out: dict[str, float] = {}
    for key, value in raw.items():
        sd = model.sd.get(key, 0.0)
        if sd < 1e-12:
            continue  # a dimension identical across the corpus discriminates nothing
        out[key] = (value - model.mean.get(key, 0.0)) / sd
    return out


def _cosine(a: dict, b: dict) -> float:
    """Cosine similarity over two sparse weight vectors (may be negative)."""
    if not a or not b:
        return 0.0
    small, large = (a, b) if len(a) <= len(b) else (b, a)
    dot = sum(w * large.get(k, 0.0) for k, w in small.items())
    na = math.sqrt(sum(w * w for w in a.values()))
    nb = math.sqrt(sum(w * w for w in b.values()))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _subset(vec: dict[str, float], prefix: str) -> dict[str, float]:
    return {k: v for k, v in vec.items() if k.startswith(prefix)}


def cosine_delta(a: dict[str, float], b: dict[str, float]) -> float:
    """Cosine Delta, rescaled from [-1, 1] to [0, 1]."""
    return (_cosine(a, b) + 1.0) / 2.0


def burrows_delta(a: Profile, b: Profile, corpus: list[Profile], top_n: int = 150) -> float:
    """Classic Burrows's Delta, converted to a 0..1 similarity.

    Delta is the mean absolute difference between two authors' z-scored relative
    word frequencies, so it is a *distance*; ``1/(1+delta)`` maps it to a
    similarity. Reported alongside Cosine Delta as an independent cross-check.
    """
    counts: Counter = Counter()
    for p in corpus:
        counts.update(p.word_freqs)
    vocabulary = [w for w, _ in counts.most_common(top_n)]
    if not vocabulary:
        return 0.0

    deltas = []
    for w in vocabulary:
        series = [p.word_freqs.get(w, 0) / max(1, p.total_words) for p in corpus]
        mean = sum(series) / len(series)
        sd = math.sqrt(sum((x - mean) ** 2 for x in series) / len(series))
        if sd < 1e-12:
            continue
        za = ((a.word_freqs.get(w, 0) / max(1, a.total_words)) - mean) / sd
        zb = ((b.word_freqs.get(w, 0) / max(1, b.total_words)) - mean) / sd
        deltas.append(abs(za - zb))

    if not deltas:
        return 0.0
    return 1.0 / (1.0 + sum(deltas) / len(deltas))


#: How much each feature family contributes to the combined score. Cosine Delta
#: over character n-grams dominates because it is the measure that actually
#: separates authors; the others corroborate.
FEATURE_WEIGHTS = {
    "char_ngram_delta": 0.45,
    "word_delta": 0.30,
    "burrows_delta": 0.15,
    "structural_delta": 0.10,
}


@dataclass
class Comparison:
    handle_a: str
    handle_b: str
    score: float
    features: dict[str, float]
    reliable: bool
    note: str = ""

    #: How far this pair stands above the *rest of this run*, in robust standard
    #: deviations (see :func:`standout_scores`). This is the measure to trust:
    #: the absolute ``score`` drifts with sample length and corpus size, while
    #: standing out from the field does not.
    standout: float = 0.0

    @property
    def is_lead(self) -> bool:
        """Whether an analyst should look at this pair.

        Either signal qualifies: an absolute score in the calibrated range, or a
        pair that stands sharply apart from every other pair in the same run.
        """
        return self.score >= STYLOMETRY_MIN_SCORE or self.standout >= STANDOUT_SIGMA

    def explain(self) -> str:
        parts = ", ".join(f"{k}={v:.3f}" for k, v in sorted(self.features.items()))
        flag = "" if self.reliable else "  [LOW CONFIDENCE: short sample]"
        return (
            f"{self.handle_a} <-> {self.handle_b}: {self.score:.3f} "
            f"({self.standout:+.1f}σ vs field) ({parts}){flag}"
        )


def standout_scores(comparisons: list["Comparison"]) -> None:
    """Annotate each comparison with how far it stands above the field.

    Absolute similarity is not comparable between runs: standardizing against
    the corpus means a run with four short profiles compresses every score
    toward the middle, while a run with thirty long ones spreads them out. The
    *ranking* survives that, so the operative question is not "is this score
    high" but "does this pair stand apart from every other pair here".

    Uses the median and median absolute deviation rather than mean and standard
    deviation, because the true same-author pairs are precisely the outliers the
    statistic must not be dragged by.
    """
    scores = sorted(c.score for c in comparisons)
    n = len(scores)
    if n < 4:
        return  # too few pairs for the field to mean anything

    def _median(values: list[float]) -> float:
        m = len(values)
        mid = m // 2
        return values[mid] if m % 2 else (values[mid - 1] + values[mid]) / 2.0

    median = _median(scores)
    mad = _median(sorted(abs(x - median) for x in scores))
    # 1.4826 rescales the MAD to be a consistent estimator of sigma for normal data.
    sigma = 1.4826 * mad
    if sigma < 1e-9:
        return
    for c in comparisons:
        c.standout = round((c.score - median) / sigma, 3)


def compare(
    a: Profile,
    b: Profile,
    model: CorpusModel,
    corpus: list[Profile],
    _za: dict[str, float] | None = None,
    _zb: dict[str, float] | None = None,
) -> Comparison:
    """Compare two author profiles in the standardized feature space."""
    za = _za if _za is not None else standardize(a, model)
    zb = _zb if _zb is not None else standardize(b, model)

    features = {
        "char_ngram_delta": cosine_delta(_subset(za, "g:"), _subset(zb, "g:")),
        "word_delta": cosine_delta(_subset(za, "w:"), _subset(zb, "w:")),
        "burrows_delta": burrows_delta(a, b, corpus),
        "structural_delta": cosine_delta(_subset(za, "s:"), _subset(zb, "s:")),
    }
    score = sum(FEATURE_WEIGHTS[k] * v for k, v in features.items())
    return Comparison(
        handle_a=a.handle,
        handle_b=b.handle,
        score=round(score, 4),
        features={k: round(v, 4) for k, v in features.items()},
        reliable=a.reliable and b.reliable,
        note="" if (a.reliable and b.reliable) else
             f"samples: {a.handle}={a.length}c, {b.handle}={b.length}c "
             f"(reliable at >= {RELIABLE_CHARS}c)",
    )


class StylometryEngine:
    """Builds author profiles from stored documents and ranks handle pairs."""

    def __init__(self, storage):
        self.storage = storage
        self.profiles: dict[str, Profile] = {}

    def load_profiles(self) -> dict[str, Profile]:
        """Group every attributed document by handle and profile each author."""
        by_handle: dict[str, list[str]] = {}
        for row in self.storage.documents(with_handle=True):
            handle = (row["handle"] or "").strip()
            if handle:
                by_handle.setdefault(handle, []).append(row["text"] or "")

        self.profiles = {
            handle: build_profile(handle, texts)
            for handle, texts in by_handle.items()
        }
        skipped = [h for h, p in self.profiles.items() if not p.usable]
        if skipped:
            logger.info(
                "%d handle(s) have under %d characters of text and were skipped: %s",
                len(skipped), MIN_CHARS, ", ".join(sorted(skipped)[:10]),
            )
        self.profiles = {h: p for h, p in self.profiles.items() if p.usable}
        return self.profiles

    def run(
        self, min_score: float = 0.0, persist: bool = True
    ) -> list[Comparison]:
        """Compare every pair of usable profiles, ranked most similar first."""
        profiles = list(self.load_profiles().values())
        if len(profiles) < 2:
            logger.info(
                "Stylometry needs at least 2 handles with >= %d characters "
                "of attributed text; found %d.", MIN_CHARS, len(profiles),
            )
            return []

        model = build_corpus_model(profiles)
        # Standardize once per profile rather than once per pair.
        z = {p.handle: standardize(p, model) for p in profiles}

        results: list[Comparison] = []
        for i in range(len(profiles)):
            for j in range(i + 1, len(profiles)):
                a, b = profiles[i], profiles[j]
                cmp_ = compare(a, b, model, profiles, z[a.handle], z[b.handle])
                if cmp_.score >= min_score:
                    results.append(cmp_)

        results.sort(key=lambda c: -c.score)
        standout_scores(results)
        if persist:
            for c in results:
                self.storage.add_stylometry_pair(
                    c.handle_a, c.handle_b, c.score, "cosine-delta(char+word+struct)",
                    {
                        **c.features, "reliable": c.reliable,
                        "note": c.note, "standout": c.standout,
                    },
                )
        logger.info(
            "Stylometry: compared %d handle(s) -> %d pair(s)", len(profiles), len(results)
        )
        return results
