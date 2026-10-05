"""Unified-diff helpers: find which new-file line numbers a patch adds."""
from __future__ import annotations

import re

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def added_lines(patch: str) -> set[int]:
    """Line numbers (new-file side) added by a single-file patch, as returned by GitHub."""
    result: set[int] = set()
    new = 0
    in_hunk = False
    for raw in patch.splitlines():
        m = HUNK_RE.match(raw)
        if m:
            new, in_hunk = int(m.group(1)), True
            continue
        if not in_hunk or raw.startswith("\\"):
            continue
        if raw.startswith("+"):
            result.add(new)
            new += 1
        elif raw.startswith("-"):
            continue
        else:
            new += 1
    return result


def parse_unified_diff(diff: str) -> dict[str, set[int]]:
    """Split a multi-file `git diff` into {path: added line numbers}."""
    out: dict[str, set[int]] = {}
    chunks: list[tuple[str | None, list[str]]] = []
    current: tuple[str | None, list[str]] | None = None
    in_hunk = False
    for raw in diff.splitlines():
        if raw.startswith("diff --git"):
            current = (None, [])
            chunks.append(current)
            in_hunk = False
            continue
        if current is None:
            continue
        if not in_hunk and raw.startswith("+++ "):
            name = raw[4:].strip()
            current = (name[2:] if name.startswith("b/") else None if name == "/dev/null" else name, current[1])
            chunks[-1] = current
            continue
        if HUNK_RE.match(raw):
            in_hunk = True
        if in_hunk:
            current[1].append(raw)
    for path, body in chunks:
        if path:
            out[path] = added_lines("\n".join(body))
    return out
