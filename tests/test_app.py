import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from crassist.app import create_app
from crassist.metrics_store import MetricsStore, seed_demo
from crassist.reviewer import CodeReviewer
from tests.test_github import make


@pytest.fixture
def store(tmp_path):
    return MetricsStore(str(tmp_path / "app.db"))


def sign(body: bytes, secret="s"):
    return {"x-hub-signature-256": "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()}


def test_dashboard_and_api(store):
    seed_demo(store, n=10)
    c = TestClient(create_app(store, CodeReviewer(), make(), "s"))
    assert "Code quality" in c.get("/").text
    assert c.get("/health").json() == {"status": "ok"}
    assert c.get("/api/summary").json()["reviews"] == 10
    for ep in ("trend", "rules", "files", "reviews"):
        assert isinstance(c.get(f"/api/{ep}").json(), list)


def test_snippet_review_endpoint(store):
    c = TestClient(create_app(store, CodeReviewer(), make(), "s"))
    r = c.post("/api/review", json={"code": "eval('1')\n"}).json()
    assert r["findings"][0]["rule"] == "dangerous-eval" and r["score"] < 100


def test_webhook_signature_required(store):
    c = TestClient(create_app(store, CodeReviewer(), make(), "s"))
    assert c.post("/webhook/github", content=b"{}", headers={"x-github-event": "ping"}).status_code == 401
    ok = c.post("/webhook/github", content=b"{}", headers={"x-github-event": "ping", **sign(b"{}")})
    assert ok.json() == {"msg": "pong"}


def test_webhook_refuses_when_unconfigured(store, monkeypatch):
    monkeypatch.delenv("CRA_ALLOW_UNSIGNED", raising=False)
    c = TestClient(create_app(store, CodeReviewer(), make(), ""))
    assert c.post("/webhook/github", content=b"{}").status_code == 503


def test_webhook_pr_event_runs_review(store):
    client = make()
    c = TestClient(create_app(store, CodeReviewer(), client, "s"))
    payload = json.dumps({"action": "opened", "number": 7, "repository": {"full_name": "o/r"},
                          "pull_request": {"draft": False, "head": {"sha": "deadbeef"}}}).encode()
    r = c.post("/webhook/github", content=payload, headers={"x-github-event": "pull_request", **sign(payload)})
    assert r.json() == {"status": "queued"}
    assert store.summary()["reviews"] == 1
    assert any(u.endswith("/pulls/7/reviews") for _, u, _ in client.session.calls)
