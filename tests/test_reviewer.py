from crassist.models import Finding, quality_score
from crassist.reviewer import CodeReviewer, FileInput

BAD = "def f(x, y=[]):\n    return eval(x)\n"


class FakeBackend:
    def __init__(self, findings=None, error=None):
        self.findings, self.error, self.calls = findings or [], error, 0

    def review(self, path, code, changed_lines=None):
        self.calls += 1
        if self.error:
            raise self.error
        return self.findings


def test_static_only_sorted_by_severity():
    r = CodeReviewer().review_source("a.py", BAD)
    assert r.findings[0].severity == "high"
    assert r.severity_counts["high"] == 1 and r.score < 100


def test_changed_lines_filter():
    r = CodeReviewer().review_source("a.py", BAD, changed_lines={1})
    assert {f.rule for f in r.findings} == {"mutable-default-arg"}


def test_llm_findings_merged_and_deduped():
    llm = [Finding("a.py", 2, "code-exec", "high", "eval executes arbitrary code", "llm"),
           Finding("a.py", 1, "naming", "info", "rename function to something descriptive", "llm")]
    r = CodeReviewer(FakeBackend(llm)).review_source("a.py", BAD)
    rules = [f.rule for f in r.findings]
    assert "code-exec" not in rules and "naming" in rules and "dangerous-eval" in rules


def test_llm_failure_becomes_warning():
    r = CodeReviewer(FakeBackend(error=RuntimeError("boom"))).review_source("a.py", BAD)
    assert r.findings and "LLM review failed" in r.warnings[0]


def test_llm_file_limit():
    b = FakeBackend()
    r = CodeReviewer(b, max_llm_files=1).review_files([FileInput("a.py", "x=1\n"), FileInput("b.py", "y=2\n")])
    assert b.calls == 1 and any("skipped" in w for w in r.warnings)


def test_score_bounds_and_markdown():
    assert quality_score([], 100) == 100
    many = [Finding("a", 1, "r", "high", "m")] * 50
    assert quality_score(many, 10) == 0
    md = CodeReviewer().review_source("a.py", BAD).summary_markdown()
    assert "Quality score" in md and "a.py:2" in md
    assert "No issues" in CodeReviewer().review_source("a.py", "x = 1\n").summary_markdown()
