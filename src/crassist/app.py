"""FastAPI app: GitHub webhook receiver + dashboard + JSON API."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .github_integration import HANDLED_ACTIONS, GitHubClient, handle_pull_request_event, verify_signature
from .llm_review import get_backend
from .metrics_store import MetricsStore
from .reviewer import CodeReviewer

log = logging.getLogger("crassist.app")
DASHBOARD = Path(__file__).parent / "static" / "dashboard.html"


class SnippetRequest(BaseModel):
    path: str = "snippet.py"
    code: str
    use_llm: bool = False


def create_app(store: MetricsStore | None = None, reviewer: CodeReviewer | None = None,
               client: GitHubClient | None = None, webhook_secret: str | None = None) -> FastAPI:
    store = store or MetricsStore(os.environ.get("CRA_DB", "crassist.db"))
    reviewer = reviewer or CodeReviewer(backend=get_backend(os.environ.get("CRA_BACKEND", "none")))
    secret = webhook_secret if webhook_secret is not None else os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    allow_unsigned = os.environ.get("CRA_ALLOW_UNSIGNED") == "1"
    app = FastAPI(title="Code Review Assistant")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        return DASHBOARD.read_text(encoding="utf-8")

    @app.get("/api/summary")
    def summary():
        return store.summary()

    @app.get("/api/trend")
    def trend(days: int = 30):
        return store.trend(max(1, min(days, 365)))

    @app.get("/api/rules")
    def rules():
        return store.top_rules()

    @app.get("/api/files")
    def files():
        return store.worst_files()

    @app.get("/api/reviews")
    def reviews(limit: int = 15):
        return store.recent_reviews(max(1, min(limit, 100)))

    @app.post("/api/review")
    def review_snippet(req: SnippetRequest):
        if len(req.code) > 100_000:
            raise HTTPException(413, "snippet too large")
        r = reviewer if req.use_llm else CodeReviewer(thresholds=reviewer.thresholds)
        return r.review_source(req.path, req.code).to_dict()

    def _process(payload: dict):
        try:
            handle_pull_request_event(payload, reviewer, client or GitHubClient(), store)
        except Exception:
            log.exception("PR review failed")

    @app.post("/webhook/github")
    async def github_webhook(request: Request, background: BackgroundTasks):
        body = await request.body()
        if secret:
            if not verify_signature(secret, body, request.headers.get("x-hub-signature-256")):
                raise HTTPException(401, "invalid signature")
        elif not allow_unsigned:
            raise HTTPException(503, "GITHUB_WEBHOOK_SECRET is not configured")
        event = request.headers.get("x-github-event")
        if event == "ping":
            return {"msg": "pong"}
        if event != "pull_request":
            return {"status": "ignored", "event": event}
        payload = json.loads(body)
        if payload.get("action") not in HANDLED_ACTIONS:
            return {"status": "ignored", "action": payload.get("action")}
        background.add_task(_process, payload)
        return {"status": "queued"}

    return app


def app_factory() -> FastAPI:  # for `uvicorn crassist.app:app_factory --factory`
    return create_app()
