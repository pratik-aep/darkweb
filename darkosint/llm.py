"""AI-assisted analysis with Claude.

Regex extraction finds identifiers that *look* like identifiers. It cannot read
a forum post that says "shipping from Rotterdam, back after Eid, my old account
got banned last year" and understand that it just disclosed a location, a
probable religious calendar, and the existence of a prior handle. That is the
gap this module fills.

Three capabilities, each with a strict output schema so the result is parseable
rather than prose:

:func:`LlmEnricher.extract_claims`
    Pulls self-disclosed facts out of unstructured text — claimed locations,
    languages, shipping origins, time references, prior handles, contact
    preferences, and operational-security slips.
:func:`LlmEnricher.assess_actor`
    Given a resolved cluster and its evidence, writes an attribution assessment:
    does the evidence actually support one operator, what is the strongest link,
    and what would falsify it.
:func:`LlmEnricher.assess_correlation`
    Reviews an onion→clearnet correlation the way a reviewer would, including
    the innocent explanations (shared host, shared CDN, copied template).

Discipline
----------
* Model output is **a lead, never evidence**. Everything stored from here is
  flagged ``heuristic`` and typed ``llm_*`` so it can never be mistaken for a
  parsed artifact.
* The model is explicitly instructed to distinguish *what the text claims* from
  *what is true*, and to return empty rather than guess.
* Only page text already collected is sent — this module never fetches anything.
* The SDK is imported lazily and every method degrades to an empty result, so
  the rest of the toolkit runs unchanged with no API key present.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from .extractors import Identifier

logger = logging.getLogger("darkosint.llm")

DEFAULT_MODEL = "claude-opus-5"

# Identifier types produced here. The ``llm_`` prefix is load-bearing: it keeps
# inferred claims separable from parsed artifacts at query time.
LLM_CLAIMED_LOCATION = "llm_claimed_location"
LLM_CLAIMED_LANGUAGE = "llm_claimed_language"
LLM_ALIAS_CLAIM = "llm_alias_claim"
LLM_CONTACT_PREF = "llm_contact_pref"
LLM_OPSEC_SLIP = "llm_opsec_slip"
LLM_VENDOR_ROLE = "llm_vendor_role"

#: Schema for claim extraction. ``additionalProperties: false`` plus a full
#: ``required`` list is what makes the structured-output guarantee hold.
CLAIMS_SCHEMA = {
    "type": "object",
    "properties": {
        "handles": {
            "type": "array",
            "description": "Usernames/handles the text presents as belonging to an actor.",
            "items": {
                "type": "object",
                "properties": {
                    "handle": {"type": "string"},
                    "role": {
                        "type": "string",
                        "description": "vendor, buyer, admin, moderator, or unknown",
                    },
                    "quote": {"type": "string", "description": "Supporting excerpt."},
                },
                "required": ["handle", "role", "quote"],
                "additionalProperties": False,
            },
        },
        "claimed_locations": {
            "type": "array",
            "description": "Places the text claims an actor is in or ships from.",
            "items": {
                "type": "object",
                "properties": {
                    "place": {"type": "string"},
                    "kind": {
                        "type": "string",
                        "description": "residence, shipping_origin, shipping_destination, or mention",
                    },
                    "handle": {"type": "string", "description": "Handle it belongs to, or ''."},
                    "quote": {"type": "string"},
                },
                "required": ["place", "kind", "handle", "quote"],
                "additionalProperties": False,
            },
        },
        "languages": {
            "type": "array",
            "description": "Languages evidenced by the writing, including L1 interference.",
            "items": {
                "type": "object",
                "properties": {
                    "language": {"type": "string"},
                    "basis": {"type": "string", "description": "Why — the specific cue."},
                },
                "required": ["language", "basis"],
                "additionalProperties": False,
            },
        },
        "prior_handles": {
            "type": "array",
            "description": "References to accounts an actor says they used before.",
            "items": {
                "type": "object",
                "properties": {
                    "handle": {"type": "string"},
                    "current_handle": {"type": "string"},
                    "quote": {"type": "string"},
                },
                "required": ["handle", "current_handle", "quote"],
                "additionalProperties": False,
            },
        },
        "contact_methods": {
            "type": "array",
            "description": "Contact channels named in the text (platform names, not values).",
            "items": {
                "type": "object",
                "properties": {
                    "platform": {"type": "string"},
                    "value": {"type": "string", "description": "The address/ID if stated, else ''."},
                    "quote": {"type": "string"},
                },
                "required": ["platform", "value", "quote"],
                "additionalProperties": False,
            },
        },
        "opsec_slips": {
            "type": "array",
            "description": (
                "Statements that narrow who or where the actor is: timezone or "
                "working-hours references, local events, currency, dialect, "
                "platform habits, or a detail inconsistent with their claims."
            ),
            "items": {
                "type": "object",
                "properties": {
                    "observation": {"type": "string"},
                    "why_it_narrows": {"type": "string"},
                    "quote": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": ["observation", "why_it_narrows", "quote", "confidence"],
                "additionalProperties": False,
            },
        },
    },
    "required": [
        "handles", "claimed_locations", "languages",
        "prior_handles", "contact_methods", "opsec_slips",
    ],
    "additionalProperties": False,
}

ASSESSMENT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "description": "one_actor, likely_one_actor, insufficient, or likely_separate",
        },
        "confidence": {"type": "number"},
        "strongest_link": {"type": "string"},
        "reasoning": {"type": "string"},
        "alternative_explanations": {"type": "array", "items": {"type": "string"}},
        "what_would_falsify": {"type": "array", "items": {"type": "string"}},
        "recommended_next_steps": {"type": "array", "items": {"type": "string"}},
    },
    "required": [
        "verdict", "confidence", "strongest_link", "reasoning",
        "alternative_explanations", "what_would_falsify", "recommended_next_steps",
    ],
    "additionalProperties": False,
}

EXTRACTION_SYSTEM = """\
You are an analyst supporting an authorized dark web threat-intelligence \
investigation. You are given text collected from a marketplace or forum page.

Extract only what the text itself states or directly evidences. Follow these rules:

1. Distinguish CLAIM from FACT. A vendor saying "shipping from Germany" is a claim \
about shipping origin, not a finding about where they live. Record it as claimed.
2. Quote your evidence. Every item needs a short verbatim excerpt from the input. \
If you cannot quote it, do not report it.
3. Return empty arrays rather than guessing. A page with no self-disclosure should \
produce empty arrays. Inventing plausible-sounding findings is the worst outcome.
4. Do not infer identity from names. "Dmitri" does not establish nationality.
5. For opsec_slips, confidence is how strongly the observation narrows the actor, \
from 0.0 to 1.0. Be conservative; most pages contain nothing of the kind.

You are describing what a document says. You are not making an attribution."""

ASSESSMENT_SYSTEM = """\
You are a senior analyst reviewing an attribution hypothesis in an authorized \
investigation. You are shown a cluster of identifiers that an automated graph \
merged into one actor, plus the evidence that caused each merge.

Your job is to be the skeptic. Specifically:

1. Weigh the evidence by KIND, not by quantity. One shared PGP fingerprint \
outweighs twenty co-occurrences on a busy index page.
2. Name the innocent explanation. Shared hosting, a copied site template, a \
recycled avatar, two people using one shop account, a handle common enough to \
collide — say so when it fits.
3. Stylometric similarity and co-occurrence are corroboration, never proof.
4. State plainly when the evidence is insufficient. "insufficient" is a correct \
and useful verdict.
5. what_would_falsify must be concrete and checkable, not generic advice."""


@dataclass
class ClaimResult:
    """Structured claims extracted from one page, plus the raw model payload."""

    identifiers: list[Identifier] = field(default_factory=list)
    raw: dict = field(default_factory=dict)
    error: str = ""
    usage: dict = field(default_factory=dict)


class LlmUnavailable(RuntimeError):
    """Raised when the Anthropic SDK or credentials are not usable."""


class LlmEnricher:
    """Claude-backed enrichment over already-collected text."""

    #: Page text is truncated to this many characters per request. Truncation is
    #: reported rather than silent, so a long page can be chunked deliberately.
    MAX_CHARS = 60_000

    def __init__(self, storage=None, model: str = DEFAULT_MODEL, client=None):
        self.storage = storage
        self.model = model
        self._client = client

    # ---- client -----------------------------------------------------------

    @property
    def client(self):
        """Lazily construct the Anthropic client.

        The zero-argument constructor resolves credentials from the environment
        or from an ``ant auth login`` profile, so no key is read or stored here.
        """
        if self._client is None:
            try:
                import anthropic
            except ImportError as exc:
                raise LlmUnavailable(
                    "The anthropic SDK is not installed. Install it with "
                    "`pip install anthropic` to enable AI analysis."
                ) from exc
            try:
                self._client = anthropic.Anthropic()
            except Exception as exc:  # noqa: BLE001 - surfaces missing credentials
                raise LlmUnavailable(f"Could not create an Anthropic client: {exc}") from exc
        return self._client

    def available(self) -> bool:
        """True if an enrichment call could be made right now."""
        try:
            _ = self.client
            return True
        except LlmUnavailable as exc:
            logger.debug("LLM enrichment unavailable: %s", exc)
            return False

    # ---- internal ---------------------------------------------------------

    def _structured(
        self,
        system: str,
        user: str,
        schema: dict,
        max_tokens: int = 8000,
        thinking: bool = False,
    ) -> tuple[dict, dict]:
        """One structured-output request; returns ``(parsed_json, usage)``."""
        kwargs: dict = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "output_config": {"format": {"type": "json_schema", "schema": schema}},
        }
        if thinking:
            # Attribution reasoning is exactly the kind of weighing that benefits
            # from adaptive thinking.
            kwargs["thinking"] = {"type": "adaptive"}

        response = self.client.messages.create(**kwargs)

        if getattr(response, "stop_reason", None) == "refusal":
            details = getattr(response, "stop_details", None)
            raise LlmUnavailable(
                f"Request declined by safety classifier "
                f"(category={getattr(details, 'category', None)})"
            )

        text = next(
            (b.text for b in response.content if getattr(b, "type", "") == "text"), ""
        )
        usage = {
            "input_tokens": getattr(response.usage, "input_tokens", 0),
            "output_tokens": getattr(response.usage, "output_tokens", 0),
        }
        try:
            return json.loads(text), usage
        except json.JSONDecodeError as exc:
            raise LlmUnavailable(f"Model returned unparseable JSON: {exc}") from exc

    def _truncate(self, text: str) -> tuple[str, bool]:
        if len(text) <= self.MAX_CHARS:
            return text, False
        return text[: self.MAX_CHARS], True

    # ---- capability 1: claim extraction -----------------------------------

    def extract_claims(self, text: str, url: str = "") -> ClaimResult:
        """Extract self-disclosed claims from one page's text."""
        result = ClaimResult()
        if not (text or "").strip():
            return result

        body, truncated = self._truncate(text)
        if truncated:
            logger.info("Page text truncated to %d chars for analysis", self.MAX_CHARS)

        prompt = (
            f"Source URL: {url or 'unknown'}\n"
            f"{'NOTE: text was truncated for length.' if truncated else ''}\n\n"
            f"--- BEGIN COLLECTED PAGE TEXT ---\n{body}\n--- END COLLECTED PAGE TEXT ---"
        )
        try:
            data, usage = self._structured(EXTRACTION_SYSTEM, prompt, CLAIMS_SCHEMA)
        except LlmUnavailable as exc:
            result.error = str(exc)
            logger.warning("Claim extraction failed for %s: %s", url or "?", exc)
            return result

        result.raw = data
        result.usage = usage
        result.identifiers = self._claims_to_identifiers(data, url)
        return result

    @staticmethod
    def _claims_to_identifiers(data: dict, url: str) -> list[Identifier]:
        """Map the model's structured claims onto flagged Identifier rows."""
        out: list[Identifier] = []
        where = f" [{url}]" if url else ""

        for item in data.get("handles", []):
            handle = (item.get("handle") or "").strip()
            if handle:
                out.append(Identifier(
                    LLM_VENDOR_ROLE, f"{handle}:{item.get('role', 'unknown')}",
                    context=f"LLM: {item.get('quote', '')}{where}", heuristic=True,
                ))
        for item in data.get("claimed_locations", []):
            place = (item.get("place") or "").strip()
            if place:
                out.append(Identifier(
                    LLM_CLAIMED_LOCATION, place,
                    context=f"LLM ({item.get('kind', 'mention')}, "
                            f"handle={item.get('handle') or '?'}): "
                            f"{item.get('quote', '')}{where}",
                    heuristic=True,
                ))
        for item in data.get("languages", []):
            lang = (item.get("language") or "").strip()
            if lang:
                out.append(Identifier(
                    LLM_CLAIMED_LANGUAGE, lang,
                    context=f"LLM: {item.get('basis', '')}{where}", heuristic=True,
                ))
        for item in data.get("prior_handles", []):
            prior = (item.get("handle") or "").strip()
            if prior:
                out.append(Identifier(
                    LLM_ALIAS_CLAIM, prior,
                    context=f"LLM: claimed prior handle of "
                            f"{item.get('current_handle') or '?'} — "
                            f"{item.get('quote', '')}{where}",
                    heuristic=True,
                ))
        for item in data.get("contact_methods", []):
            platform = (item.get("platform") or "").strip()
            if platform:
                value = (item.get("value") or "").strip()
                out.append(Identifier(
                    LLM_CONTACT_PREF, f"{platform}:{value}" if value else platform,
                    context=f"LLM: {item.get('quote', '')}{where}", heuristic=True,
                ))
        for item in data.get("opsec_slips", []):
            obs = (item.get("observation") or "").strip()
            if obs:
                out.append(Identifier(
                    LLM_OPSEC_SLIP, obs,
                    context=f"LLM (confidence {item.get('confidence', 0)}): "
                            f"{item.get('why_it_narrows', '')} — "
                            f"{item.get('quote', '')}{where}",
                    heuristic=True,
                ))
        return out

    def enrich_documents(self, limit: int = 20, min_chars: int = 400) -> int:
        """Run claim extraction across stored documents; returns rows added."""
        if self.storage is None:
            raise ValueError("enrich_documents needs a Storage instance")

        added = 0
        processed = 0
        for row in self.storage.documents(with_handle=False):
            if processed >= limit:
                break
            text = row["text"] or ""
            if len(text) < min_chars:
                continue
            processed += 1
            result = self.extract_claims(text, row["url"] or "")
            if result.identifiers and row["source_id"]:
                added += self.storage.add_identifiers(row["source_id"], result.identifiers)
        logger.info(
            "LLM enrichment: %d document(s) analysed, %d new claim(s) stored",
            processed, added,
        )
        return added

    # ---- capability 2: actor assessment -----------------------------------

    def assess_actor(self, actor) -> dict:
        """Review a resolved actor cluster and return a structured assessment."""
        prompt = (
            "Assess whether this cluster of identifiers represents a single "
            "operator.\n\n"
            f"{actor.explain()}\n\n"
            "Consider how each edge type was derived:\n"
            "  pgp_uid       — a name/email read from inside the key's own UID "
            "packet (cryptographically bound to the key)\n"
            "  co_occurrence — identifiers appearing on the same page, damped by "
            "how many identifiers that page held\n"
            "  stylometry    — writing-style similarity, calibrated to roughly "
            "80% precision on short samples\n"
            "  trust_link    — a vouch/feedback relationship parsed from a site"
        )
        try:
            data, _ = self._structured(
                ASSESSMENT_SYSTEM, prompt, ASSESSMENT_SCHEMA,
                max_tokens=16000, thinking=True,
            )
            return data
        except LlmUnavailable as exc:
            logger.warning("Actor assessment failed for %s: %s", actor.label, exc)
            return {"error": str(exc)}

    # ---- capability 3: correlation review ---------------------------------

    def assess_correlation(self, finding) -> dict:
        """Review an onion→clearnet correlation, innocent explanations included."""
        prompt = (
            "Assess this hypothesis linking a Tor hidden service to clearnet "
            "infrastructure.\n\n"
            f"{finding.explain()}\n\n"
            "Weigh especially: could shared hosting, a shared CDN, a copied site "
            "template, a default distribution banner, or a public template's "
            "analytics ID explain this without the two being operated by the same "
            "party? Treat a clearnet name inside the hidden service's own TLS "
            "certificate as far stronger than any shared banner or referenced domain."
        )
        try:
            data, _ = self._structured(
                ASSESSMENT_SYSTEM, prompt, ASSESSMENT_SCHEMA,
                max_tokens=16000, thinking=True,
            )
            return data
        except LlmUnavailable as exc:
            logger.warning(
                "Correlation assessment failed for %s: %s", finding.onion_host, exc
            )
            return {"error": str(exc)}
