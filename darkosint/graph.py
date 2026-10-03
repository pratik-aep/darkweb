"""Actor entity resolution and relationship graph.

Turns a pile of identifiers into a claim of the form *"these handles, keys and
wallets belong to one actor, and here is why"*.

Model
-----
* **Node** — one ``(type, value)`` identifier. The same value seen on five
  marketplaces is *one* node observed five times; that multiplicity is the
  cross-market signal, not five separate things.
* **Edge** — weighted, typed, and evidence-bearing:

  ``pgp_uid``
      A parsed key's fingerprint to the name/email inside its User ID packet.
      Near-certain: the binding is cryptographic, not inferred.
  ``co_occurrence``
      Two identifiers published on the same page. Damped by how crowded that
      page is — a vendor profile listing one PGP key and one wallet is strong
      evidence; a forum index listing two hundred handles is almost none.
  ``stylometry``
      Two handles whose writing matches (see :mod:`darkosint.stylometry`).
  ``trust_link``
      A vouch / feedback edge a site-specific parser extracted.

* **Actor** — a connected component over edges at or above a threshold.

Every merge keeps the edges that justified it, so an analyst can audit *why* two
handles were joined and reject the ones that do not hold up. Nothing here is
treated as ground truth: clusters carry a confidence, and a cluster built only
from co-occurrence and stylometry is explicitly marked as weak.
"""
from __future__ import annotations

import json
import logging
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from xml.sax.saxutils import escape as xml_escape

from .stylometry import STANDOUT_SIGMA, STYLOMETRY_MIN_SCORE
from .extractors import (
    BTC_ADDRESS,
    EMAIL,
    ETH_ADDRESS,
    ONION_URL,
    PGP_BLOCK,
    PGP_FINGERPRINT,
    USERNAME,
    XMPP,
    XMR_ADDRESS,
)
from .fingerprints import (
    ANALYTICS_ID,
    CLEARNET_DOMAIN,
    S3_BUCKET,
    TLS_SPKI,
)

logger = logging.getLogger("darkosint.graph")

PGP_UID_EMAIL = "pgp_uid_email"
PGP_UID_NAME = "pgp_uid_name"
TRUST_REF = "trust_ref"

#: How uniquely each identifier type pins down one human operator. These are
#: priors, deliberately explicit so an analyst can argue with them.
TYPE_STRENGTH: dict[str, float] = {
    PGP_FINGERPRINT: 1.00,   # cryptographic identity
    TLS_SPKI: 0.92,
    PGP_UID_EMAIL: 0.90,
    EMAIL: 0.88,
    XMPP: 0.88,
    XMR_ADDRESS: 0.85,
    BTC_ADDRESS: 0.85,
    ETH_ADDRESS: 0.80,
    ANALYTICS_ID: 0.75,
    PGP_UID_NAME: 0.70,
    S3_BUCKET: 0.60,
    USERNAME: 0.45,          # handles collide; never ground truth on their own
    CLEARNET_DOMAIN: 0.35,
    PGP_BLOCK: 0.30,         # superseded by the parsed fingerprint
    ONION_URL: 0.15,
}

#: Types admitted to the graph at all. Infrastructure banners are excluded —
#: they attribute a *server*, which is the correlation engine's job, not a person.
LINKABLE_TYPES = frozenset(TYPE_STRENGTH)

#: Below this, a type is corroboration only and never anchors a cluster by itself.
STRONG_THRESHOLD = 0.80

DEFAULT_EDGE_THRESHOLD = 0.35

#: An identifier that appears on this many pages of a single host — and on most
#: of that host's pages — is treated as site furniture (a footer email, a shared
#: support handle, a template analytics tag), not a per-actor artifact. Its
#: co-occurrence contribution is damped so one shared boilerplate node cannot
#: merge every vendor on a market into a single phantom actor.
BOILERPLATE_MIN_PAGES = 3


def node_key(type_: str, value: str) -> tuple[str, str]:
    return (type_, value)


@dataclass
class Edge:
    a: tuple[str, str]
    b: tuple[str, str]
    weight: float
    method: str
    evidence: dict = field(default_factory=dict)


@dataclass
class Actor:
    """A resolved cluster of identifiers believed to be one operator."""

    id: int
    members: list[tuple[str, str]] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)
    confidence: float = 0.0
    label: str = ""
    #: Per-member attachment confidence: how strongly each identifier is bound to
    #: the cluster's anchor, i.e. the weakest link on the path that reaches it.
    #: A near-certain core (key+email) and a wallet that attaches at 0.5 are then
    #: distinguishable instead of hidden behind one cluster-wide number.
    attachment: dict[tuple[str, str], float] = field(default_factory=dict)

    @property
    def strong_members(self) -> list[tuple[str, str]]:
        return [m for m in self.members if TYPE_STRENGTH.get(m[0], 0) >= STRONG_THRESHOLD]

    def choose_label(self) -> str:
        """Name the actor after its most identifying member."""
        if not self.members:
            return f"actor-{self.id}"
        best = max(
            self.members,
            key=lambda m: (TYPE_STRENGTH.get(m[0], 0.0), -len(m[1])),
        )
        type_, value = best
        if type_ == PGP_FINGERPRINT:
            return f"PGP:{value[-16:]}"
        if type_ in (EMAIL, PGP_UID_EMAIL, XMPP):
            return value
        if type_ == USERNAME:
            return f"@{value}"
        return f"{type_}:{value[:24]}"

    def explain(self) -> str:
        """Analyst-readable justification for this cluster."""
        lines = [
            f"{self.label}  (confidence {self.confidence:.2f}, "
            f"{len(self.members)} identifiers across {len(self.hosts)} host(s))"
        ]
        for type_, value in sorted(
            self.members, key=lambda m: -TYPE_STRENGTH.get(m[0], 0.0)
        ):
            flag = "" if TYPE_STRENGTH.get(type_, 0) >= STRONG_THRESHOLD else "   [weak]"
            att = self.attachment.get((type_, value))
            att_s = f"  (attaches at {att:.2f})" if att is not None and att < 0.999 else ""
            lines.append(f"    {type_:18} {value}{flag}{att_s}")
        if self.hosts:
            lines.append(f"    seen on: {', '.join(sorted(self.hosts))}")
        lines.append("    evidence:")
        for e in sorted(self.edges, key=lambda e: -e.weight)[:12]:
            lines.append(
                f"      [{e.method} {e.weight:.2f}] "
                f"{e.a[0]}:{e.a[1]}  <->  {e.b[0]}:{e.b[1]}"
                + (f"  ({e.evidence.get('detail')})" if e.evidence.get("detail") else "")
            )
        return "\n".join(lines)


class _UnionFind:
    """Disjoint-set over hashable node keys, with path compression."""

    def __init__(self) -> None:
        self.parent: dict[tuple[str, str], tuple[str, str]] = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:  # path compression
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a, b) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _bottleneck_and_attachments(
    actor: "Actor",
) -> tuple[float, dict[tuple[str, str], float]]:
    """Weakest necessary link of a cluster, and each member's attachment to it.

    Builds the maximum spanning tree over the cluster's edges (Kruskal, heaviest
    first). Its smallest edge is the *bottleneck*: the weakest link that holds
    the whole cluster together. Each member's attachment is the smallest edge on
    the tree path from it to the cluster's strongest anchor — so the key+email
    core can read near-certain while a loosely-linked wallet reads at 0.5.
    """
    nodes = list(actor.members)
    if len(nodes) < 2 or not actor.edges:
        return 0.0, {}

    uf = _UnionFind()
    adjacency: dict[tuple[str, str], list[tuple[tuple[str, str], float]]] = defaultdict(list)
    tree_weights: list[float] = []
    for edge in sorted(actor.edges, key=lambda e: -e.weight):
        if uf.find(edge.a) != uf.find(edge.b):
            uf.union(edge.a, edge.b)
            adjacency[edge.a].append((edge.b, edge.weight))
            adjacency[edge.b].append((edge.a, edge.weight))
            tree_weights.append(edge.weight)

    bottleneck = min(tree_weights) if tree_weights else 0.0

    # Anchor the attachment walk on the most identifying member.
    anchor = max(nodes, key=lambda m: TYPE_STRENGTH.get(m[0], 0.0))
    attachment: dict[tuple[str, str], float] = {anchor: 1.0}
    queue: deque[tuple[str, str]] = deque([anchor])
    while queue:
        node = queue.popleft()
        for neighbour, weight in adjacency[node]:
            if neighbour not in attachment:
                attachment[neighbour] = round(min(attachment[node], weight), 4)
                queue.append(neighbour)
    for member in nodes:  # members in a disjoint fragment (shouldn't happen)
        attachment.setdefault(member, 0.0)
    return bottleneck, attachment


class ActorGraph:
    """Builds the identifier graph and resolves it into actors."""

    def __init__(self, storage, edge_threshold: float = DEFAULT_EDGE_THRESHOLD):
        self.storage = storage
        self.edge_threshold = edge_threshold
        self.edges: list[Edge] = []
        self.nodes: dict[tuple[str, str], dict] = {}
        self.actors: list[Actor] = []
        self._edge_index: dict[tuple, Edge] = {}

    # ---- node/edge construction -------------------------------------------

    def _touch(self, type_: str, value: str, host: str = "") -> tuple[str, str]:
        key = node_key(type_, value)
        entry = self.nodes.setdefault(
            key, {"type": type_, "value": value, "hosts": set(), "sources": 0}
        )
        if host:
            entry["hosts"].add(host)
        entry["sources"] += 1
        return key

    def _add_edge(self, a, b, weight: float, method: str, evidence: dict) -> None:
        """Add an edge, keeping only the strongest one per (pair, method).

        The same key is stored once per source it was seen on, so a naive append
        emits one identical ``pgp_uid`` edge per sighting. Collapsing them keeps
        the evidence list readable and stops repeat sightings from masquerading
        as independent corroboration in :meth:`_score`.
        """
        if a == b or weight <= 0:
            return
        key = (*sorted([a, b]), method)
        existing = self._edge_index.get(key)
        if existing is not None:
            if weight > existing.weight:
                existing.weight = weight
                existing.evidence = evidence
            return
        edge = Edge(a=a, b=b, weight=weight, method=method, evidence=evidence)
        self._edge_index[key] = edge
        self.edges.append(edge)

    def _build_pgp_edges(self) -> None:
        """Bind each PGP fingerprint to the identities inside its own UID packets."""
        for row in self.storage.pgp_keys():
            fpr = row["fingerprint"]
            host = (row["host"] or "").lower()
            fpr_node = self._touch(PGP_FINGERPRINT, fpr, host)
            try:
                emails = json.loads(row["emails"] or "[]")
                names = json.loads(row["names"] or "[]")
            except (json.JSONDecodeError, TypeError):
                emails, names = [], []
            for email in emails:
                if not email:
                    continue
                node = self._touch(PGP_UID_EMAIL, email.lower(), host)
                self._add_edge(
                    fpr_node, node, 0.98, "pgp_uid",
                    {"detail": f"email {email!r} is inside the User ID packet of key {fpr[-16:]}"},
                )
            for name in names:
                if not name:
                    continue
                node = self._touch(PGP_UID_NAME, name, host)
                self._add_edge(
                    fpr_node, node, 0.90, "pgp_uid",
                    {"detail": f"name {name!r} is inside the User ID packet of key {fpr[-16:]}"},
                )

    def _boilerplate_factors(self) -> dict[tuple[str, str, str], float]:
        """Per-(host, type, value) damping factor for site-furniture identifiers.

        An identifier that recurs on most of a host's pages is boilerplate — a
        footer contact, a shared support handle, a template's analytics tag — not
        a per-actor artifact. Left undamped, one such shared node co-occurs with
        every vendor's key and merges them all into one phantom actor. Something
        seen on a single page keeps full weight; something on most pages of a
        multi-page host is scaled down by how promiscuous it is.
        """
        hosts = self.storage.source_hosts()
        host_pages: dict[str, int] = defaultdict(int)
        value_pages: dict[tuple[str, str, str], int] = defaultdict(int)
        for sid, rows in self.storage.identifiers_by_source().items():
            host = (hosts.get(sid) or "").lower()
            host_pages[host] += 1
            for key in {(host, r["type"], r["value"]) for r in rows}:
                value_pages[key] += 1

        factors: dict[tuple[str, str, str], float] = {}
        for key, pages in value_pages.items():
            host = key[0]
            total = host_pages.get(host, 1)
            # Boilerplate only when it recurs a lot AND covers most of the host.
            if pages >= max(BOILERPLATE_MIN_PAGES, math.ceil(0.6 * total)):
                factors[key] = 1.0 / pages
            else:
                factors[key] = 1.0
        return factors

    def _build_cooccurrence_edges(self) -> None:
        """Link identifiers published together, damped by page crowding.

        Two guards keep co-occurrence honest:

        * **Same strong type is a listing, not a person.** Two PGP fingerprints
          (or two emails) on one page are a directory of different operators, so
          they are never linked to each other by mere co-occurrence.
        * **Boilerplate is damped.** A node that recurs across a host's pages
          contributes little, so a shared footer cannot merge a whole market.
        """
        hosts = self.storage.source_hosts()
        boiler = self._boilerplate_factors()
        for source_id, rows in self.storage.identifiers_by_source().items():
            host = (hosts.get(source_id) or "").lower()
            usable = [r for r in rows if r["type"] in LINKABLE_TYPES]
            if len(usable) < 2:
                for r in usable:
                    self._touch(r["type"], r["value"], host)
                continue

            # A page listing hundreds of identifiers says almost nothing about
            # which of them belong together; one listing two says a great deal.
            # The decay is deliberately gentle (log2 scaled by 3): a vendor
            # profile carrying a key, a handle and a wallet must still link them,
            # while a forum index carrying forty handles must not.
            crowding = 1.0 / (1.0 + math.log2(max(2, len(usable))) / 3.0)

            keys = [self._touch(r["type"], r["value"], host) for r in usable]
            # Cap the pairwise expansion: beyond this a page is an index, not a
            # profile, and every pair would be noise anyway.
            if len(keys) > 40:
                continue
            for i in range(len(keys)):
                for j in range(i + 1, len(keys)):
                    ta, tb = keys[i][0], keys[j][0]
                    # Two identifiers of the same strong type on one page are a
                    # listing of distinct operators, not one person's profile.
                    if ta == tb and TYPE_STRENGTH.get(ta, 0.0) >= STRONG_THRESHOLD:
                        continue
                    sa = TYPE_STRENGTH.get(ta, 0.0)
                    sb = TYPE_STRENGTH.get(tb, 0.0)
                    damp = min(
                        boiler.get((host, keys[i][0], keys[i][1]), 1.0),
                        boiler.get((host, keys[j][0], keys[j][1]), 1.0),
                    )
                    # Geometric mean, not the product: multiplying both strengths
                    # penalises a strong-plus-moderate pair twice and stopped a
                    # vendor page from linking its own key to its own handle.
                    weight = round(0.9 * crowding * damp * math.sqrt(sa * sb), 4)
                    self._add_edge(
                        keys[i], keys[j], weight, "co_occurrence",
                        {
                            "detail": f"published together on {host} "
                                      f"(source {source_id}, {len(usable)} identifiers on page)",
                            "source_id": source_id,
                        },
                    )

    def _build_stylometry_edges(self, min_score: float = STYLOMETRY_MIN_SCORE) -> None:
        """Promote stored stylometric matches into handle-to-handle edges.

        A pair qualifies on either signal: an absolute score in the calibrated
        range, or standing sharply apart from every other pair in its own run.
        The second matters because absolute scores compress when the corpus is
        small — exactly the situation early in an investigation.
        """
        for row in self.storage.stylometry_pairs(min_score=0.0):
            try:
                features = json.loads(row["features"] or "{}")
            except (json.JSONDecodeError, TypeError):
                features = {}
            standout = float(features.get("standout") or 0.0)
            if row["score"] < min_score and standout < STANDOUT_SIGMA:
                continue

            a = self._touch(USERNAME, row["handle_a"])
            b = self._touch(USERNAME, row["handle_b"])
            # Map similarity onto a conservative edge weight: a perfect stylistic
            # match is still not an identity proof, so it is capped below the
            # weight a cryptographic identifier earns.
            basis = max(row["score"], min(1.0, min_score + (standout - STANDOUT_SIGMA) * 0.05))
            weight = round(min(0.75, 0.45 + (basis - min_score) * 1.2), 4)
            self._add_edge(
                a, b, weight, "stylometry",
                {
                    "detail": f"writing style similarity {row['score']:.3f}, "
                              f"{standout:+.1f}σ above the other pairs compared "
                              f"({row['method']})",
                    "score": row["score"],
                    "standout": standout,
                },
            )

    def _build_trust_edges(self) -> None:
        """Ingest trust/vouch edges recorded by site-specific parsers."""
        for row in self.storage.actor_edges():
            if row["method"] != "trust_link":
                continue
            a = self._touch(row["a_type"], row["a_value"])
            b = self._touch(row["b_type"], row["b_value"])
            try:
                evidence = json.loads(row["evidence"] or "{}")
            except (json.JSONDecodeError, TypeError):
                evidence = {}
            self._add_edge(a, b, float(row["weight"]), "trust_link", evidence)

    # ---- resolution -------------------------------------------------------

    def build(self) -> list[Actor]:
        """Construct the graph and resolve connected components into actors."""
        self.edges.clear()
        self.nodes.clear()
        self._edge_index.clear()

        self._build_pgp_edges()
        self._build_cooccurrence_edges()
        self._build_stylometry_edges()
        self._build_trust_edges()

        # Resolve with a union that refuses contradictory merges. Two *distinct*
        # PGP fingerprints are two different cryptographic identities; nothing
        # short of direct strong evidence should fuse them, so a weak edge (a
        # shared page, a shared footer contact, a style match) may not merge two
        # components that each already hold a distinct key-identity. Strong
        # edges (a name/email bound inside a key's own UID packet) still merge.
        # Heaviest edges are considered first so real structure forms before
        # weak evidence fills the gaps.
        weak_methods = {"co_occurrence", "stylometry", "trust_link"}
        uf = _UnionFind()
        for key in self.nodes:
            uf.find(key)
        anchors: dict[tuple[str, str], set[str]] = defaultdict(set)
        for key in self.nodes:
            if key[0] == PGP_FINGERPRINT:
                anchors[uf.find(key)].add(key[1])

        for edge in sorted(self.edges, key=lambda e: -e.weight):
            if edge.weight < self.edge_threshold:
                continue
            ra, rb = uf.find(edge.a), uf.find(edge.b)
            if ra == rb:
                continue
            if edge.method in weak_methods and len(anchors[ra] | anchors[rb]) >= 2:
                logger.debug(
                    "Refusing weak %s merge: would fuse distinct key-identities %s",
                    edge.method, anchors[ra] | anchors[rb],
                )
                continue
            merged = anchors[ra] | anchors[rb]
            uf.union(edge.a, edge.b)
            root = uf.find(edge.a)
            anchors.pop(ra, None)
            anchors.pop(rb, None)
            anchors[root] = merged

        # Keep the edges that ended up internal to a resolved component.
        kept: list[Edge] = [
            e for e in self.edges
            if e.weight >= self.edge_threshold and uf.find(e.a) == uf.find(e.b)
        ]

        groups: dict[tuple[str, str], list[tuple[str, str]]] = {}
        for key in self.nodes:
            groups.setdefault(uf.find(key), []).append(key)

        actors: list[Actor] = []
        for i, (_, members) in enumerate(
            sorted(groups.items(), key=lambda kv: -len(kv[1])), start=1
        ):
            # A lone identifier is an observation, not a resolved actor.
            if len(members) < 2:
                continue
            member_set = set(members)
            actor = Actor(id=i, members=sorted(members))
            actor.edges = [e for e in kept if e.a in member_set and e.b in member_set]
            for m in members:
                actor.hosts |= self.nodes[m]["hosts"]
            actor.confidence = self._score(actor)
            actor.label = actor.choose_label()
            actors.append(actor)

        self.actors = actors
        logger.info(
            "Actor resolution: %d actor(s) from %d node(s) and %d edge(s) "
            "(threshold %.2f)",
            len(actors), len(self.nodes), len(kept), self.edge_threshold,
        )
        return actors

    def _score(self, actor: Actor) -> float:
        """Confidence that a cluster really is one operator.

        A cluster is a chain of claims and is only as strong as its weakest
        *necessary* link. So the base is the bottleneck of the maximum spanning
        tree over the cluster — the smallest edge you cannot avoid using to hold
        every member together — not the single best edge, which would let one
        rock-solid PGP binding lend its confidence to a wallet three weak hops
        away. A strong cryptographic anchor still helps, and corroboration from
        more than one method still helps; a cluster of handles joined only by
        co-occurrence still scores low. Per-member attachment is recorded on the
        actor so the strong core and the weak fringe stay distinguishable.
        """
        if not actor.edges:
            return 0.0
        bottleneck, attach = _bottleneck_and_attachments(actor)
        actor.attachment = attach
        has_strong_anchor = bool(actor.strong_members)
        anchor_bonus = 0.15 if has_strong_anchor else -0.20
        # Corroboration from more than one *method* is worth more than more
        # edges of the same kind.
        distinct_methods = len({e.method for e in actor.edges})
        method_bonus = 0.05 * (distinct_methods - 1)
        score = bottleneck + anchor_bonus + method_bonus
        return round(max(0.0, min(0.99, score)), 4)

    # ---- persistence & export ---------------------------------------------

    def persist(self) -> int:
        """Write the resolved actors and their edges back to the database."""
        for edge in self.edges:
            if edge.weight >= self.edge_threshold and edge.method != "trust_link":
                self.storage.add_actor_edge(
                    edge.a, edge.b, edge.weight, edge.method, edge.evidence
                )
        clusters = [
            {
                "label": a.label,
                "confidence": a.confidence,
                "method": "identifier-graph",
                "notes": f"{len(a.members)} identifiers across {len(a.hosts)} host(s)",
                "evidence": [
                    {
                        "method": e.method,
                        "weight": e.weight,
                        "a": list(e.a),
                        "b": list(e.b),
                        "detail": e.evidence.get("detail", ""),
                    }
                    for e in sorted(a.edges, key=lambda e: -e.weight)[:25]
                ],
                "members": [
                    (t, v, round(a.attachment.get((t, v), TYPE_STRENGTH.get(t, 0.0)), 4))
                    for t, v in a.members
                ],
            }
            for a in self.actors
        ]
        return self.storage.replace_actors(clusters)

    def to_dict(self) -> dict:
        """Serializable graph: nodes, edges, and resolved actors."""
        actor_of: dict[tuple[str, str], int] = {}
        for actor in self.actors:
            for m in actor.members:
                actor_of[m] = actor.id
        return {
            "nodes": [
                {
                    "id": f"{t}:{v}",
                    "type": t,
                    "value": v,
                    "strength": TYPE_STRENGTH.get(t, 0.0),
                    "hosts": sorted(meta["hosts"]),
                    "observations": meta["sources"],
                    "actor": actor_of.get((t, v)),
                }
                for (t, v), meta in self.nodes.items()
            ],
            "edges": [
                {
                    "source": f"{e.a[0]}:{e.a[1]}",
                    "target": f"{e.b[0]}:{e.b[1]}",
                    "weight": e.weight,
                    "method": e.method,
                    "detail": e.evidence.get("detail", ""),
                }
                for e in self.edges if e.weight >= self.edge_threshold
            ],
            "actors": [
                {
                    "id": a.id,
                    "label": a.label,
                    "confidence": a.confidence,
                    "hosts": sorted(a.hosts),
                    "members": [{"type": t, "value": v} for t, v in a.members],
                    "explanation": a.explain(),
                }
                for a in self.actors
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)

    def to_graphml(self) -> str:
        """GraphML export — opens directly in Gephi, yEd, or Cytoscape."""
        data = self.to_dict()
        out = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '  <key id="type" for="node" attr.name="type" attr.type="string"/>',
            '  <key id="value" for="node" attr.name="value" attr.type="string"/>',
            '  <key id="actor" for="node" attr.name="actor" attr.type="string"/>',
            '  <key id="strength" for="node" attr.name="strength" attr.type="double"/>',
            '  <key id="weight" for="edge" attr.name="weight" attr.type="double"/>',
            '  <key id="method" for="edge" attr.name="method" attr.type="string"/>',
            '  <graph id="darkosint" edgedefault="undirected">',
        ]
        for n in data["nodes"]:
            out.append(f'    <node id="{xml_escape(n["id"])}">')
            out.append(f'      <data key="type">{xml_escape(n["type"])}</data>')
            out.append(f'      <data key="value">{xml_escape(n["value"])}</data>')
            out.append(f'      <data key="actor">{n["actor"] if n["actor"] else ""}</data>')
            out.append(f'      <data key="strength">{n["strength"]}</data>')
            out.append('    </node>')
        for i, e in enumerate(data["edges"]):
            out.append(
                f'    <edge id="e{i}" source="{xml_escape(e["source"])}" '
                f'target="{xml_escape(e["target"])}">'
            )
            out.append(f'      <data key="weight">{e["weight"]}</data>')
            out.append(f'      <data key="method">{xml_escape(e["method"])}</data>')
            out.append('    </edge>')
        out.append('  </graph>')
        out.append('</graphml>')
        return "\n".join(out)

    def to_dot(self) -> str:
        """Graphviz DOT export, coloured by actor cluster."""
        data = self.to_dict()
        palette = [
            "#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f",
            "#edc948", "#b07aa1", "#ff9da7", "#9c755f", "#bab0ac",
        ]
        out = ["graph darkosint {", '  overlap=false; splines=true; node [shape=box, style=filled];']
        for n in data["nodes"]:
            colour = palette[(n["actor"] or 0) % len(palette)] if n["actor"] else "#dddddd"
            label = f'{n["type"]}\\n{n["value"][:28]}'
            out.append(f'  "{n["id"]}" [label="{label}", fillcolor="{colour}"];')
        for e in data["edges"]:
            style = "solid" if e["weight"] >= 0.7 else "dashed"
            out.append(
                f'  "{e["source"]}" -- "{e["target"]}" '
                f'[label="{e["method"]} {e["weight"]:.2f}", style={style}, '
                f'penwidth={max(1.0, e["weight"] * 4):.1f}];'
            )
        out.append("}")
        return "\n".join(out)
