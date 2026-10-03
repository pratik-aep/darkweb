"""A flaky onion service must not crash the crawler.

Regression for a real fault a live crawl hit: urllib3 raises ProtocolError /
IncompleteRead while draining a truncated response, which is not a
requests.RequestException and previously escaped the retry loop and killed the
whole run. It must instead be retried and surfaced as a failed fetch.
"""
import urllib3

from darkosint.config import Config
from darkosint.tor_session import TorSession


class _BrokenRaw:
    def read(self, *a, **k):
        raise urllib3.exceptions.ProtocolError(
            "Connection broken: IncompleteRead(30035 bytes read, 21877 more expected)"
        )


class _Resp:
    ok = False
    status_code = 200
    url = "http://x.onion/"
    encoding = "utf-8"
    headers = {}
    raw = _BrokenRaw()

    def close(self):
        pass


def test_truncated_response_is_retried_not_raised():
    cfg = Config().with_overrides(**{
        "http.max_retries": 1, "http.timeout": 1, "tor.rotate_every": 0,
    })
    session = TorSession(cfg)
    session._session.get = lambda *a, **k: _Resp()  # inject the flaky response

    result = session.get("http://x.onion/")  # must not raise
    assert result.ok is False
    assert "ProtocolError" in result.error
