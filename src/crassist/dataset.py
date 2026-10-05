"""Training-data loading, validation and formatting (no heavy dependencies)."""
from __future__ import annotations

import json
from pathlib import Path

from .models import SEVERITY_RANK
from .prompts import render_plain_prompt


def load_jsonl(path: str | Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as e:
                    raise ValueError(f"{path}:{n}: invalid JSON ({e})") from e
    return rows


def validate_example(ex: dict) -> list[str]:
    errs = []
    for key in ("path", "code", "findings"):
        if key not in ex:
            errs.append(f"missing '{key}'")
    if errs:
        return errs
    n_lines = len(ex["code"].splitlines())
    if not isinstance(ex["findings"], list):
        return ["'findings' must be a list"]
    for i, f in enumerate(ex["findings"]):
        if not isinstance(f.get("line"), int) or not 1 <= f["line"] <= n_lines:
            errs.append(f"finding {i}: line out of range 1..{n_lines}")
        if f.get("severity") not in SEVERITY_RANK:
            errs.append(f"finding {i}: bad severity {f.get('severity')!r}")
        if not f.get("rule") or not f.get("message"):
            errs.append(f"finding {i}: rule and message are required")
    return errs


def validate_dataset(rows: list[dict]) -> list[str]:
    return [f"example {i}: {e}" for i, ex in enumerate(rows) for e in validate_example(ex)]


def format_example(ex: dict) -> tuple[str, str]:
    """Return (prompt, completion) for supervised fine-tuning."""
    prompt = render_plain_prompt(ex["path"], ex["code"])
    completion = json.dumps({"findings": ex["findings"]}, ensure_ascii=False)
    return prompt, completion
