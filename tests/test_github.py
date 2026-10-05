import hashlib
import hmac

import pytest
import requests

from crassist.github_integration import (GitHubClient, format_comment, handle_pull_request_event,
                                          review_pull_request, verify_signature)
from crassist.metrics_store import MetricsStore
from crassist.reviewer import CodeReviewer

CONTENT = "import os\n\ndef f(x, y=[]):\n    return eval(x)\n"
PATCH = "@@ -0,0 +1,4 @@\n+import os\n+\n+def f(x, y=[]):\n+    return eval(x)\n"


class Resp:
    def __init__(self, data=None, text="", status=200):
        self._d, self.text, self.status_code = data, text, status

    def json(self): return self._d

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)


class FakeSession:
    def __init__(self, reject_inline=False):
        self.calls, self.reject_inline = [], reject_inline

    def request(self, method, url, headers=None, params=None, json=None, timeout=None):
        self.calls.append((method, url, json))
        if url.endswith("/pulls/7"):
            return Resp({"head": {"sha": "deadbeef"}})
        if url.endswith("/pulls/7/files"):
            return Resp([{"filename": "a.py", "status": "added", "patch": PATCH},
                         {"filename": "README.md", "status": "modified", "patch": "@@ -1 +1 @@\n+x"},
                         {"filename": "old.py", "status": "removed", "patch": "@@ -1 +0,0 @@\n-x"}])
        if "/contents/" in url:
            return Resp(text=CONTENT)
        if url.endswith("/pulls/7/reviews"):
            if self.reject_inline and json.get("comments"):
                return Resp(status=422)
            return Resp({"id": 1})
        raise AssertionError(url)


def make(session=None):
    return GitHubClient("tok", session or FakeSession())


def test_signature():
    body = b'{"a":1}'
    good = "sha256=" + hmac.new(b"s", body, hashlib.sha256).hexdigest()
    assert verify_signature("s", body, good)
    assert not verify_signature("s", body, "sha256=bad")
    assert not verify_signature("s", body, None) and not verify_signature("", body, good)


def test_review_pull_request_posts_inline_comments(tmp_path):
    client, store = make(), MetricsStore(str(tmp_path / "g.db"))
    result = review_pull_request(client, CodeReviewer(), "o", "r", 7, store=store)
    assert {f.rule for f in result.findings} >= {"dangerous-eval", "mutable-default-arg"}
    method, url, payload = client.session.calls[-1]
    assert (method, payload["commit_id"], payload["event"]) == ("POST", "deadbeef", "COMMENT")
    assert all(c["side"] == "RIGHT" and c["line"] in (1, 3, 4) for c in payload["comments"])
    contents = [c for c in client.session.calls if "/contents/" in c[1]]
    assert len(contents) == 1  # README.md and removed files were skipped
    assert store.summary()["reviews"] == 1


def test_dry_run_does_not_post():
    client = make()
    review_pull_request(client, CodeReviewer(), "o", "r", 7, post=False)
    assert not any(u.endswith("/reviews") for _, u, _ in client.session.calls)


def test_falls_back_to_summary_on_422():
    client = make(FakeSession(reject_inline=True))
    review_pull_request(client, CodeReviewer(), "o", "r", 7)
    posts = [p for m, u, p in client.session.calls if u.endswith("/reviews")]
    assert len(posts) == 2 and "comments" not in posts[1]


def test_event_filtering():
    payload = {"action": "closed", "number": 7, "repository": {"full_name": "o/r"}, "pull_request": {"head": {"sha": "x"}}}
    assert handle_pull_request_event(payload, CodeReviewer(), make()) is None
    payload.update(action="opened", pull_request={"draft": True, "head": {"sha": "x"}})
    assert handle_pull_request_event(payload, CodeReviewer(), make()) is None


def test_format_comment():
    from crassist.models import Finding
    text = format_comment(Finding("a.py", 1, "r", "high", "msg", suggestion="do x"))
    assert "HIGH" in text and "msg" in text and "do x" in text
