from crassist.metrics_store import MetricsStore, seed_demo
from crassist.reviewer import CodeReviewer


def test_record_and_aggregate(tmp_path):
    store = MetricsStore(str(tmp_path / "t.db"))
    assert store.summary()["reviews"] == 0 and store.summary()["avg_score"] is None
    result = CodeReviewer().review_source("a.py", "def f(x, y=[]):\n    return eval(x)\n")
    store.record_review(result, repo="o/r", pr_number=5, sha="abc")
    store.record_review(CodeReviewer().review_source("b.py", "x = 1\n"), repo="o/r", pr_number=6)
    s = store.summary()
    assert s["reviews"] == 2 and s["severity"]["high"] == 1 and s["by_source"] == {"static": 2}
    assert store.recent_reviews(1)[0]["pr_number"] == 6
    assert {r["rule"] for r in store.top_rules()} == {"dangerous-eval", "mutable-default-arg"}
    assert store.worst_files()[0]["path"] == "a.py"
    assert len(store.trend(7)) == 1


def test_seed_demo(tmp_path):
    store = MetricsStore(str(tmp_path / "d.db"))
    seed_demo(store, n=20)
    assert store.summary()["reviews"] == 20 and len(store.trend(30)) > 5
