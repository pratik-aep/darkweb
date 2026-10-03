"""The generic parser must recover attributed posts from stock forum markup,
so stylometry and temporal analysis work on real crawls, not just seeded data.
"""
from darkosint.parsers import get_parser_for

_PHPBB = """
<html><body>
<div class="post"><div class="postbody">
  <p class="author"><a class="username">nightferry</a> »
     <time datetime="2026-03-02T19:14:00+00:00">Mon Mar 02, 2026 7:14 pm</time></p>
  <div class="content">Right so listen. Stock is in. I ship monday, tuesday latest, no refunds.
     <blockquote><cite>harbourlight wrote:</cite> is it here yet</blockquote></div>
</div></div>
<div class="post"><div class="postbody">
  <p class="author"><a class="username-coloured">harbourlight</a> »
     <time datetime="2026-03-03T20:41:00+00:00">Tue Mar 03, 2026 8:41 pm</time></p>
  <div class="content">Quick update for everyone, prices going up next week, thats just how it is.</div>
</div></div>
</body></html>
"""


def test_generic_parser_attributes_forum_posts():
    parser = get_parser_for("http://someforumxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion/t/1")
    result = parser.parse("http://someforumxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion/t/1", _PHPBB)

    docs = {handle: text for handle, text, _ in result.documents}
    assert set(docs) == {"nightferry", "harbourlight"}, "posts not attributed to authors"
    # Quoted text must be stripped from the author's own sample.
    assert "is it here yet" not in docs["nightferry"]
    # Timestamps carry through for temporal analysis.
    stamps = {handle: ts for handle, _, ts in result.documents}
    assert stamps["nightferry"].startswith("2026-03-02T19:14")
    # Both handles surface as username identifiers, and the quote becomes an edge.
    handles = {i.value for i in result.identifiers if i.type == "username_candidate"}
    assert {"nightferry", "harbourlight"} <= handles
    assert any(e[0] == "nightferry" and e[1] == "harbourlight" for e in result.trust_edges)


def test_non_forum_page_keeps_anonymous_document():
    parser = get_parser_for("http://plainxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion/")
    html = "<html><body><h1>Welcome</h1><p>Just a plain landing page with prose.</p></body></html>"
    result = parser.parse("http://plainxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion/", html)
    # No forum structure -> the single anonymous page document is preserved.
    assert all(handle is None for handle, _, _ in result.documents)
