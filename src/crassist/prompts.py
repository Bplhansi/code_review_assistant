"""Prompt templates shared by inference (LLM backends) and LoRA training."""
from __future__ import annotations

SYSTEM = (
    "You are a meticulous senior engineer doing code review. Report only real, actionable problems: "
    "bugs, security issues, resource leaks, concurrency hazards, performance traps and maintainability "
    "problems. Do not nitpick formatting. If the code is fine, return no findings.\n"
    'Respond with ONLY JSON: {"findings": [{"line": <int>, "severity": "info|low|medium|high", '
    '"rule": "<kebab-case-id>", "message": "<what is wrong and why>", "suggestion": "<how to fix>"}]}. '
    "Line numbers refer to the numbered listing."
)

MAX_CODE_CHARS = 24_000


def number_lines(code: str) -> str:
    return "\n".join(f"{i:>4}: {line}" for i, line in enumerate(code.splitlines(), 1))


def build_prompt(path: str, code: str, changed_lines: set[int] | None = None) -> str:
    listing = number_lines(code[:MAX_CODE_CHARS])
    hint = ""
    if changed_lines:
        hint = f"\nFocus on these changed lines: {', '.join(map(str, sorted(changed_lines)))}.\n"
    return f"File: {path}{hint}\n```\n{listing}\n```"


def render_plain_prompt(path: str, code: str, changed_lines: set[int] | None = None) -> str:
    """Single-string prompt used for LoRA training and local inference (no chat template needed)."""
    return f"{SYSTEM}\n\n{build_prompt(path, code, changed_lines)}\n\n### Response:\n"
