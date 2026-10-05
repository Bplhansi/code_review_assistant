"""Orchestrates static analysis + LLM review into one scored result."""
from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass, field

from .llm_review import LLMBackend
from .models import SEVERITIES, SEVERITY_RANK, FileMetrics, Finding, quality_score
from .static_analysis import Thresholds, analyze_source

log = logging.getLogger("crassist")


@dataclass
class FileInput:
    path: str
    content: str
    changed_lines: set[int] | None = None  # None = review the whole file


@dataclass
class ReviewResult:
    findings: list[Finding] = field(default_factory=list)
    metrics: list[FileMetrics] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def loc(self) -> int:
        return sum(m.loc for m in self.metrics)

    @property
    def score(self) -> float:
        return quality_score(self.findings, self.loc)

    @property
    def severity_counts(self) -> dict[str, int]:
        c = Counter(f.severity for f in self.findings)
        return {s: c.get(s, 0) for s in SEVERITIES}

    @property
    def avg_complexity(self) -> float:
        funcs = sum(m.functions for m in self.metrics)
        if not funcs:
            return 0.0
        return round(sum(m.avg_complexity * m.functions for m in self.metrics) / funcs, 2)

    def to_dict(self) -> dict:
        return {
            "score": self.score, "loc": self.loc, "files": len(self.metrics),
            "avg_complexity": self.avg_complexity, "severity_counts": self.severity_counts,
            "findings": [f.to_dict() for f in self.findings], "warnings": self.warnings,
        }

    def summary_markdown(self, limit: int = 15) -> str:
        c = self.severity_counts
        lines = [
            "### Code review",
            f"**Quality score: {self.score:.0f}/100** ({len(self.metrics)} files, {self.loc} LOC; "
            f"{c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info)",
            "",
        ]
        if not self.findings:
            lines.append("No issues found in the changed lines.")
        else:
            lines += ["| Severity | Location | Issue |", "|---|---|---|"]
            for f in self.findings[:limit]:
                msg = f.message.replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {f.severity} | `{f.path}:{f.line}` | {msg} ({f.source}) |")
            if len(self.findings) > limit:
                lines.append(f"\n…and {len(self.findings) - limit} more.")
        lines += [f"\n> Note: {w}" for w in self.warnings]
        return "\n".join(lines)


def _words(s: str) -> set[str]:
    return set(re.findall(r"[a-z]{3,}", s.lower()))


def _similar(a: Finding, b: Finding) -> bool:
    if a.path != b.path or abs(a.line - b.line) > 1:
        return False
    wa, wb = _words(a.message + " " + a.rule), _words(b.message + " " + b.rule)
    return bool(wa and wb) and len(wa & wb) / len(wa | wb) >= 0.3


class CodeReviewer:
    def __init__(self, backend: LLMBackend | None = None, thresholds: Thresholds | None = None,
                 max_llm_files: int = 20, llm_extensions: tuple[str, ...] | None = None):
        self.backend = backend
        self.thresholds = thresholds or Thresholds()
        self.max_llm_files = max_llm_files
        self.llm_extensions = llm_extensions

    def review_files(self, files: list[FileInput]) -> ReviewResult:
        result = ReviewResult()
        llm_calls = 0
        for f in files:
            static, metrics = analyze_source(f.path, f.content, self.thresholds)
            result.metrics.append(metrics)
            if f.changed_lines is not None:
                static = [x for x in static if x.line in f.changed_lines]
            llm: list[Finding] = []
            if self.backend and (not self.llm_extensions or f.path.endswith(self.llm_extensions)):
                if llm_calls >= self.max_llm_files:
                    result.warnings.append(f"LLM review skipped for {f.path} (limit of {self.max_llm_files} files).")
                else:
                    llm_calls += 1
                    try:
                        llm = self.backend.review(f.path, f.content, f.changed_lines)
                    except Exception as e:  # network/model failures must not break the review
                        log.warning("LLM review failed for %s: %s", f.path, e)
                        result.warnings.append(f"LLM review failed for {f.path}: {type(e).__name__}")
                    if f.changed_lines is not None:
                        llm = [x for x in llm if x.line in f.changed_lines]
            result.findings.extend(static)
            result.findings.extend(x for x in llm if not any(_similar(x, s) for s in static))
        result.findings.sort(key=lambda x: (-SEVERITY_RANK[x.severity], x.path, x.line))
        return result

    def review_source(self, path: str, content: str, changed_lines: set[int] | None = None) -> ReviewResult:
        return self.review_files([FileInput(path, content, changed_lines)])
