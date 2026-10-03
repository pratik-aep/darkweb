"""Unit tests for the SQLite storage/query API."""
from darkosint.extractors import BTC_ADDRESS, Identifier, USERNAME
from darkosint.storage import Storage


def make_db(tmp_path):
    return Storage(tmp_path / "test.db")


def test_add_source_snapshot_identifiers(tmp_path):
    with make_db(tmp_path) as db:
        sid = db.add_source(
            url="http://x.onion/", host="x.onion", site="generic", http_status=200
        )
        db.add_snapshot(sid, path="/tmp/x.html", sha256="abc", content_length=10, content_type="text/html")
        added = db.add_identifiers(
            sid,
            [
                Identifier(BTC_ADDRESS, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
                Identifier(USERNAME, "shadow", heuristic=True),
            ],
        )
        assert added == 2
        # Re-inserting identical rows is idempotent (UNIQUE constraint).
        assert db.add_identifiers(sid, [Identifier(USERNAME, "shadow")]) == 0
        assert db.source_count() == 1
        assert db.counts_by_type() == {BTC_ADDRESS: 1, USERNAME: 1}
        assert db.snapshots_for(sid)[0]["sha256"] == "abc"


def test_find_and_pivot_across_sources(tmp_path):
    with make_db(tmp_path) as db:
        wallet = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        s1 = db.add_source("http://a.onion/", "a.onion", "generic", 200)
        s2 = db.add_source("http://b.onion/", "b.onion", "generic", 200)
        db.add_identifiers(s1, [Identifier(BTC_ADDRESS, wallet)])
        db.add_identifiers(s2, [Identifier(BTC_ADDRESS, wallet)])

        # Same wallet on two sites is exactly the actor-linking signal.
        pivot = db.pivot(wallet)
        assert {r["url"] for r in pivot} == {"http://a.onion/", "http://b.onion/"}

        shared = db.shared_identifiers(min_sources=2)
        assert len(shared) == 1
        assert shared[0]["value"] == wallet
        assert shared[0]["source_count"] == 2


def test_find_handles_and_by_type(tmp_path):
    with make_db(tmp_path) as db:
        sid = db.add_source("http://a.onion/", "a.onion", "generic", 200)
        db.add_identifiers(
            sid,
            [
                Identifier(USERNAME, "darkseller99", heuristic=True),
                Identifier(BTC_ADDRESS, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            ],
        )
        assert db.find_handles("darkseller")[0]["value"] == "darkseller99"
        assert len(db.find_by_type(BTC_ADDRESS)) == 1
        assert db.find_by_value("1A1zP1", exact=False)
        assert not db.find_by_value("1A1zP1", exact=True)


def test_links_recorded(tmp_path):
    with make_db(tmp_path) as db:
        sid = db.add_source("http://a.onion/", "a.onion", "generic", 200)
        n = db.add_links(sid, "http://a.onion/", ["http://b.onion/", "http://c.onion/"])
        assert n == 2
