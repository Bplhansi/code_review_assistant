"""Command line interface: review files, review a PR, serve the dashboard, seed demo data."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from .diff_utils import parse_unified_diff
from .llm_review import get_backend
from .models import SEVERITY_RANK
from .reviewer import CodeReviewer, FileInput

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "build", "dist"}


def _collect(paths: list[str]) -> list[str]:
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                out += [os.path.join(root, n) for n in names if n.endswith(".py")]
        else:
            out.append(p)
    return sorted(out)


def _print_text(result) -> None:
    for f in result.findings:
        print(f"{f.path}:{f.line}: [{f.severity}] {f.rule}: {f.message} ({f.source})")
        if f.suggestion:
            print(f"    fix: {f.suggestion}")
    print(f"\nscore {result.score:.0f}/100, {len(result.metrics)} files, {result.loc} LOC, {result.severity_counts}")
    for w in result.warnings:
        print("warning:", w)


def cmd_review(a) -> int:
    reviewer = CodeReviewer(backend=get_backend(a.backend))
    files = []
    changed = parse_unified_diff(subprocess.check_output(["git", "diff", a.diff_base], text=True)) if a.diff_base else {}
    for path in _collect(a.paths):
        with open(path, encoding="utf-8", errors="replace") as fh:
            norm = os.path.normpath(path).replace(os.sep, "/")
            if a.diff_base and norm not in changed:
                continue
            files.append(FileInput(path, fh.read(), changed.get(norm)))
    result = reviewer.review_files(files)
    if a.db:
        from .metrics_store import MetricsStore
        MetricsStore(a.db).record_review(result, repo=a.repo)
    if a.format == "json":
        print(json.dumps(result.to_dict(), indent=2))
    elif a.format == "markdown":
        print(result.summary_markdown())
    else:
        _print_text(result)
    threshold = SEVERITY_RANK[a.fail_on] if a.fail_on else None
    return 1 if threshold is not None and any(SEVERITY_RANK[f.severity] >= threshold for f in result.findings) else 0


def cmd_pr(a) -> int:
    from .github_integration import GitHubClient, review_pull_request
    from .metrics_store import MetricsStore
    owner, repo = a.repo.split("/", 1)
    store = MetricsStore(a.db) if a.db else None
    result = review_pull_request(GitHubClient(), CodeReviewer(backend=get_backend(a.backend)), owner, repo, a.number,
                                 post=not a.dry_run, store=store)
    _print_text(result)
    return 0


def cmd_serve(a) -> int:
    import uvicorn
    os.environ["CRA_DB"] = a.db
    os.environ["CRA_BACKEND"] = a.backend
    if a.demo:
        from .metrics_store import MetricsStore, seed_demo
        store = MetricsStore(a.db)
        if store.summary()["reviews"] == 0:
            seed_demo(store)
    uvicorn.run("crassist.app:app_factory", factory=True, host=a.host, port=a.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="crassist", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    backend_default = os.environ.get("CRA_BACKEND", "none")

    r = sub.add_parser("review", help="review local files/directories")
    r.add_argument("paths", nargs="+")
    r.add_argument("--backend", default=backend_default, choices=["none", "api", "local"])
    r.add_argument("--format", default="text", choices=["text", "json", "markdown"])
    r.add_argument("--fail-on", choices=["info", "low", "medium", "high"], help="exit 1 if a finding is at least this severe")
    r.add_argument("--diff-base", help="only review lines changed vs this git ref (e.g. origin/main)")
    r.add_argument("--db", help="record the review in this SQLite DB for the dashboard")
    r.add_argument("--repo", default="local")
    r.set_defaults(fn=cmd_review)

    pr = sub.add_parser("pr", help="review a GitHub pull request and post comments")
    pr.add_argument("repo", help="owner/name")
    pr.add_argument("number", type=int)
    pr.add_argument("--backend", default=backend_default, choices=["none", "api", "local"])
    pr.add_argument("--db", default=os.environ.get("CRA_DB"))
    pr.add_argument("--dry-run", action="store_true", help="print findings instead of posting")
    pr.set_defaults(fn=cmd_pr)

    s = sub.add_parser("serve", help="run the dashboard + GitHub webhook server")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.add_argument("--db", default=os.environ.get("CRA_DB", "crassist.db"))
    s.add_argument("--backend", default=backend_default, choices=["none", "api", "local"])
    s.add_argument("--demo", action="store_true", help="seed demo data if the database is empty")
    s.set_defaults(fn=cmd_serve)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
