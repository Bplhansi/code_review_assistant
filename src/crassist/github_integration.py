"""GitHub PR integration: REST client, webhook verification, and the PR review flow."""
from __future__ import annotations

import hashlib
import hmac
import logging
import os

import requests

from .diff_utils import added_lines
from .reviewer import CodeReviewer, FileInput, ReviewResult

log = logging.getLogger("crassist.github")

HANDLED_ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review"}
REVIEWABLE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".rb", ".rs", ".c", ".cpp", ".cs", ".php"}
MAX_INLINE_COMMENTS = 30


class GitHubClient:
    API = "https://api.github.com"

    def __init__(self, token: str | None = None, session: requests.Session | None = None):
        self.token = token or os.environ.get("GITHUB_TOKEN", "")
        self.session = session or requests.Session()

    def _request(self, method: str, path: str, accept: str = "application/vnd.github+json", **kw):
        headers = {"Authorization": f"Bearer {self.token}", "Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
        resp = self.session.request(method, f"{self.API}{path}", headers=headers, timeout=30, **kw)
        resp.raise_for_status()
        return resp

    def get_pull(self, owner: str, repo: str, number: int) -> dict:
        return self._request("GET", f"/repos/{owner}/{repo}/pulls/{number}").json()

    def list_pr_files(self, owner: str, repo: str, number: int, max_pages: int = 10) -> list[dict]:
        files: list[dict] = []
        for page in range(1, max_pages + 1):
            batch = self._request("GET", f"/repos/{owner}/{repo}/pulls/{number}/files",
                                  params={"per_page": 100, "page": page}).json()
            files += batch
            if len(batch) < 100:
                break
        return files

    def get_file_content(self, owner: str, repo: str, path: str, ref: str) -> str:
        return self._request("GET", f"/repos/{owner}/{repo}/contents/{path}", accept="application/vnd.github.raw+json",
                             params={"ref": ref}).text

    def post_review(self, owner, repo, number, commit_id, body, comments=None, event="COMMENT"):
        payload = {"commit_id": commit_id, "body": body, "event": event}
        if comments:
            payload["comments"] = comments
        try:
            return self._request("POST", f"/repos/{owner}/{repo}/pulls/{number}/reviews", json=payload).json()
        except requests.HTTPError as e:
            # 422 = a comment pointed at a line outside the diff; fall back to summary only.
            if comments and e.response is not None and e.response.status_code == 422:
                log.warning("Inline comments rejected, posting summary only")
                payload.pop("comments")
                return self._request("POST", f"/repos/{owner}/{repo}/pulls/{number}/reviews", json=payload).json()
            raise


def verify_signature(secret: str, body: bytes, header: str | None) -> bool:
    if not secret or not header or not header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)


def format_comment(f) -> str:
    text = f"**{f.severity.upper()}: {f.rule}** ({f.source})\n\n{f.message}"
    if f.suggestion:
        text += f"\n\nSuggestion: {f.suggestion}"
    return text


def review_pull_request(client: GitHubClient, reviewer: CodeReviewer, owner: str, repo: str, number: int,
                        head_sha: str | None = None, post: bool = True, store=None,
                        max_files: int = 40, max_bytes: int = 200_000) -> ReviewResult:
    head_sha = head_sha or client.get_pull(owner, repo, number)["head"]["sha"]
    inputs: list[FileInput] = []
    for f in client.list_pr_files(owner, repo, number):
        path = f["filename"]
        if f.get("status") == "removed" or os.path.splitext(path)[1].lower() not in REVIEWABLE_EXTENSIONS:
            continue
        changed = added_lines(f.get("patch") or "")
        if not changed:
            continue
        try:
            content = client.get_file_content(owner, repo, path, head_sha)
        except requests.RequestException as e:
            log.warning("could not fetch %s: %s", path, e)
            continue
        if len(content) <= max_bytes:
            inputs.append(FileInput(path, content, changed))
        if len(inputs) >= max_files:
            break
    result = reviewer.review_files(inputs)
    if store is not None:
        store.record_review(result, repo=f"{owner}/{repo}", pr_number=number, sha=head_sha)
    if post:
        comments = [{"path": f.path, "line": f.line, "side": "RIGHT", "body": format_comment(f)}
                    for f in result.findings[:MAX_INLINE_COMMENTS]]
        client.post_review(owner, repo, number, head_sha, result.summary_markdown(), comments)
    return result


def handle_pull_request_event(payload: dict, reviewer: CodeReviewer, client: GitHubClient, store=None):
    pr = payload.get("pull_request") or {}
    if payload.get("action") not in HANDLED_ACTIONS or pr.get("draft"):
        return None
    owner, repo = payload["repository"]["full_name"].split("/", 1)
    return review_pull_request(client, reviewer, owner, repo, payload["number"], pr["head"]["sha"], store=store)
