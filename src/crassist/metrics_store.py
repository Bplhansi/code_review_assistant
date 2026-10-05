"""SQLite persistence + aggregate queries for the dashboard."""
from __future__ import annotations

import random
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

from .models import SEVERITY_RANK, FileMetrics, Finding
from .reviewer import ReviewResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT, repo TEXT NOT NULL, pr_number INTEGER, sha TEXT,
  created_at TEXT NOT NULL, score REAL NOT NULL, files INTEGER, loc INTEGER, avg_complexity REAL,
  high INTEGER, medium INTEGER, low INTEGER, info INTEGER);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, review_id INTEGER NOT NULL REFERENCES reviews(id),
  path TEXT, line INTEGER, rule TEXT, severity TEXT, source TEXT, message TEXT);
CREATE INDEX IF NOT EXISTS idx_findings_review ON findings(review_id);
CREATE INDEX IF NOT EXISTS idx_reviews_created ON reviews(created_at);
"""


class MetricsStore:
    def __init__(self, path: str = "crassist.db"):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)

    def _all(self, sql, args=()):
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, args).fetchall()]

    def record_review(self, result: ReviewResult, repo: str = "local", pr_number: int | None = None,
                      sha: str | None = None, created_at: datetime | None = None) -> int:
        ts = (created_at or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S")
        c = result.severity_counts
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO reviews (repo,pr_number,sha,created_at,score,files,loc,avg_complexity,high,medium,low,info)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (repo, pr_number, sha, ts, result.score, len(result.metrics), result.loc, result.avg_complexity,
                 c["high"], c["medium"], c["low"], c["info"]))
            rid = cur.lastrowid
            self._conn.executemany(
                "INSERT INTO findings (review_id,path,line,rule,severity,source,message) VALUES (?,?,?,?,?,?,?)",
                [(rid, f.path, f.line, f.rule, f.severity, f.source, f.message) for f in result.findings])
        return rid

    def summary(self) -> dict:
        row = self._all("SELECT COUNT(*) n, AVG(score) s, SUM(high) h, SUM(medium) m, SUM(low) l, SUM(info) i,"
                        " AVG(avg_complexity) c, SUM(loc) loc FROM reviews")[0]
        by_source = {r["source"]: r["n"] for r in self._all("SELECT source, COUNT(*) n FROM findings GROUP BY source")}
        return {
            "reviews": row["n"] or 0,
            "avg_score": round(row["s"], 1) if row["s"] is not None else None,
            "avg_complexity": round(row["c"], 2) if row["c"] is not None else None,
            "loc_reviewed": row["loc"] or 0,
            "severity": {"high": row["h"] or 0, "medium": row["m"] or 0, "low": row["l"] or 0, "info": row["i"] or 0},
            "by_source": by_source,
        }

    def trend(self, days: int = 30) -> list[dict]:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        return self._all(
            "SELECT substr(created_at,1,10) day, ROUND(AVG(score),1) score, COUNT(*) reviews,"
            " SUM(high) high, SUM(medium) medium, SUM(low) low FROM reviews WHERE created_at >= ?"
            " GROUP BY day ORDER BY day", (since,))

    def top_rules(self, limit: int = 8) -> list[dict]:
        rows = self._all("SELECT rule, severity, COUNT(*) n FROM findings GROUP BY rule, severity")
        agg: dict[str, dict] = {}
        for r in rows:
            a = agg.setdefault(r["rule"], {"rule": r["rule"], "count": 0, "severity": r["severity"]})
            a["count"] += r["n"]
            if SEVERITY_RANK[r["severity"]] > SEVERITY_RANK[a["severity"]]:
                a["severity"] = r["severity"]
        return sorted(agg.values(), key=lambda a: -a["count"])[:limit]

    def recent_reviews(self, limit: int = 15) -> list[dict]:
        return self._all("SELECT id,repo,pr_number,sha,created_at,score,files,loc,high,medium,low,info"
                         " FROM reviews ORDER BY id DESC LIMIT ?", (limit,))

    def worst_files(self, limit: int = 8) -> list[dict]:
        return self._all("SELECT path, COUNT(*) n, SUM(CASE severity WHEN 'high' THEN 1 ELSE 0 END) high"
                         " FROM findings GROUP BY path ORDER BY high DESC, n DESC LIMIT ?", (limit,))


def seed_demo(store: MetricsStore, n: int = 45, seed: int = 7) -> None:
    """Fill the DB with plausible history so the dashboard has something to show."""
    rng = random.Random(seed)
    repos = ["acme/api", "acme/web", "acme/worker"]
    rules = [("mutable-default-arg", "medium"), ("bare-except", "medium"), ("unused-import", "low"),
             ("high-complexity", "medium"), ("sql-injection", "high"), ("missing-timeout", "low"),
             ("hardcoded-secret", "high"), ("resource-leak", "medium"), ("n-plus-one-query", "medium")]
    now = datetime.now(timezone.utc)
    for i in range(n):
        when = now - timedelta(days=(n - i) * 30 / n, hours=rng.randint(0, 8))
        improving = i / n  # simulate a team slowly improving
        findings = []
        for _ in range(max(0, int(rng.gauss(7 - 4 * improving, 2)))):
            rule, sev = rng.choice(rules)
            findings.append(Finding(rng.choice(["app/db.py", "app/views.py", "lib/utils.py", "worker/jobs.py"]),
                                    rng.randint(1, 300), rule, sev, f"Demo finding for {rule}.",
                                    source=rng.choice(["static", "llm"])))
        metrics = [FileMetrics("demo.py", loc=rng.randint(120, 600), functions=8,
                               avg_complexity=round(rng.uniform(3, 7 - 2 * improving), 2))]
        store.record_review(ReviewResult(findings, metrics), repo=rng.choice(repos), pr_number=100 + i,
                            sha=f"{rng.getrandbits(32):08x}", created_at=when)
