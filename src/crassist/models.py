"""Shared data models and scoring."""
from __future__ import annotations

from dataclasses import asdict, dataclass

SEVERITIES = ("info", "low", "medium", "high")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
SEVERITY_WEIGHT = {"info": 0.5, "low": 2.0, "medium": 5.0, "high": 10.0}

_ALIASES = {
    "critical": "high", "error": "high", "blocker": "high", "major": "medium",
    "warning": "medium", "warn": "medium", "minor": "low", "nit": "info",
    "style": "info", "suggestion": "info",
}


def normalize_severity(value) -> str:
    v = str(value or "").strip().lower()
    v = _ALIASES.get(v, v)
    return v if v in SEVERITY_RANK else "low"


@dataclass
class Finding:
    path: str
    line: int
    rule: str
    severity: str
    message: str
    source: str = "static"  # "static" | "llm"
    suggestion: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FileMetrics:
    path: str
    loc: int = 0
    functions: int = 0
    avg_complexity: float = 0.0
    max_complexity: int = 0


def quality_score(findings: list[Finding], loc: int) -> float:
    """0-100 score. Severity-weighted finding density per 100 lines (min 50 lines)."""
    weighted = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    density = weighted / max(loc, 50) * 100
    return max(0.0, round(100 - density * 2, 1))
