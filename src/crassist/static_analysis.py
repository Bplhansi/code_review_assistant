"""Fast, dependency-free static analysis built on the stdlib `ast` module.

Python files get the full rule set; every text file gets the secret scan.
Add `# noqa: cra` to a line to suppress findings reported on it.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from .models import FileMetrics, Finding

SECRET_RE = re.compile(
    r"""(?i)\b(api[_-]?key|secret|passwd|password|token|private[_-]?key)\w*\s*[:=]\s*['"]([^'"\s]{8,})['"]"""
)
PLACEHOLDER_RE = re.compile(r"(?i)(changeme|example|your[_-]|xxx|<.*>|\*{3,}|dummy|placeholder)")
HTTP_FUNCS = {f"requests.{m}" for m in ("get", "post", "put", "patch", "delete", "head", "request")}
BRANCH_NODES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.Assert)


@dataclass
class Thresholds:
    max_function_lines: int = 50
    max_complexity: int = 10
    max_args: int = 6


def cyclomatic_complexity(node: ast.AST) -> int:
    c = 1
    for n in ast.walk(node):
        if isinstance(n, BRANCH_NODES):
            c += 1
        elif isinstance(n, ast.BoolOp):
            c += len(n.values) - 1
        elif isinstance(n, ast.comprehension):
            c += 1 + len(n.ifs)
    return c


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    )


def _scan_secrets(path: str, lines: list[str]) -> list[Finding]:
    out = []
    for i, line in enumerate(lines, 1):
        m = SECRET_RE.search(line)
        if m and not PLACEHOLDER_RE.search(m.group(2)):
            out.append(Finding(path, i, "hardcoded-secret", "high",
                               f"Possible hard-coded credential in '{m.group(1)}'.",
                               suggestion="Load secrets from environment variables or a secret manager."))
    return out


def _check_function(path, node, th, findings, complexities):
    length = (node.end_lineno or node.lineno) - node.lineno + 1
    cc = cyclomatic_complexity(node)
    complexities.append(cc)
    if length > th.max_function_lines:
        findings.append(Finding(path, node.lineno, "long-function", "low",
                                f"`{node.name}` is {length} lines (limit {th.max_function_lines}).",
                                suggestion="Split into smaller, single-purpose functions."))
    if cc > th.max_complexity:
        sev = "high" if cc > th.max_complexity * 2 else "medium"
        findings.append(Finding(path, node.lineno, "high-complexity", sev,
                                f"`{node.name}` has cyclomatic complexity {cc} (limit {th.max_complexity}).",
                                suggestion="Extract branches into helpers or use early returns."))
    args = node.args
    names = [a.arg for a in args.posonlyargs + args.args + args.kwonlyargs if a.arg not in ("self", "cls")]
    if len(names) > th.max_args:
        findings.append(Finding(path, node.lineno, "too-many-args", "low",
                                f"`{node.name}` takes {len(names)} arguments (limit {th.max_args}).",
                                suggestion="Group related parameters into a dataclass."))
    for d in list(args.defaults) + [d for d in args.kw_defaults if d is not None]:
        mutable = isinstance(d, (ast.List, ast.Dict, ast.Set)) or (
            isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id in ("list", "dict", "set")
        )
        if mutable:
            findings.append(Finding(path, d.lineno, "mutable-default-arg", "medium",
                                    f"Mutable default argument in `{node.name}` is shared across calls.",
                                    suggestion="Default to None and create the object inside the function."))
    if not node.name.startswith("_") and length > 15 and not ast.get_docstring(node):
        findings.append(Finding(path, node.lineno, "missing-docstring", "info",
                                f"Public function `{node.name}` has no docstring."))


def _check_call(path, node, findings):
    name = _dotted(node.func)
    kw = {k.arg: k.value for k in node.keywords if k.arg}
    if name in ("eval", "exec"):
        findings.append(Finding(path, node.lineno, "dangerous-eval", "high",
                                f"`{name}` executes arbitrary code.",
                                suggestion="Use `ast.literal_eval` or an explicit parser."))
    elif name == "os.system":
        findings.append(Finding(path, node.lineno, "shell-injection", "high",
                                "`os.system` runs through a shell.",
                                suggestion="Use `subprocess.run([...])` with an argument list."))
    elif name.startswith("subprocess.") and isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True:
        findings.append(Finding(path, node.lineno, "shell-injection", "high",
                                "`shell=True` is vulnerable to command injection with untrusted input.",
                                suggestion="Pass an argument list and drop `shell=True`."))
    elif name in ("pickle.load", "pickle.loads"):
        findings.append(Finding(path, node.lineno, "unsafe-deserialization", "medium",
                                "Unpickling untrusted data can execute code."))
    elif name == "yaml.load" and "Loader" not in kw and len(node.args) < 2:
        findings.append(Finding(path, node.lineno, "unsafe-deserialization", "medium",
                                "`yaml.load` without a Loader is unsafe.",
                                suggestion="Use `yaml.safe_load`."))
    elif name in ("hashlib.md5", "hashlib.sha1"):
        findings.append(Finding(path, node.lineno, "weak-hash", "low",
                                f"`{name}` is cryptographically weak.",
                                suggestion="Use SHA-256 or better (and a KDF for passwords)."))
    elif name in HTTP_FUNCS and "timeout" not in kw:
        findings.append(Finding(path, node.lineno, "missing-timeout", "low",
                                f"`{name}` has no timeout and can hang forever.",
                                suggestion="Pass `timeout=` (e.g. 10)."))
    if isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany") \
            and node.args and _is_dynamic_string(node.args[0]):
        findings.append(Finding(path, node.lineno, "sql-injection", "high",
                                "SQL built with string formatting/concatenation.",
                                suggestion="Use parameterised queries: `execute(sql, params)`."))


def _unused_imports(path, tree, findings):
    if path.endswith("__init__.py"):
        return
    imported: dict[str, int] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for a in node.names:
                imported[a.asname or a.name.split(".")[0]] = node.lineno
        elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
            for a in node.names:
                if a.name != "*":
                    imported[a.asname or a.name] = node.lineno
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for name, lineno in imported.items():
        if name not in used:
            findings.append(Finding(path, lineno, "unused-import", "low", f"`{name}` is imported but never used.",
                                    suggestion="Remove the import."))


def _analyze_tree(path, tree, th, findings, metrics):
    complexities: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _check_function(path, node, th, findings, complexities)
        elif isinstance(node, ast.ExceptHandler):
            if node.type is None:
                findings.append(Finding(path, node.lineno, "bare-except", "medium",
                                        "Bare `except:` also catches KeyboardInterrupt/SystemExit.",
                                        suggestion="Catch specific exceptions (or `Exception` at minimum)."))
            if all(isinstance(s, ast.Pass) for s in node.body):
                findings.append(Finding(path, node.lineno, "swallowed-exception", "low",
                                        "Exception is silently ignored.",
                                        suggestion="Log it or handle it explicitly."))
        elif isinstance(node, ast.Call):
            _check_call(path, node, findings)
        elif isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            if any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops) and any(
                isinstance(o, ast.Constant) and o.value is None for o in operands
            ):
                findings.append(Finding(path, node.lineno, "none-comparison", "low",
                                        "Compare to None with `is` / `is not`.",
                                        suggestion="Use `is None` / `is not None`."))
    _unused_imports(path, tree, findings)
    metrics.functions = len(complexities)
    if complexities:
        metrics.avg_complexity = round(sum(complexities) / len(complexities), 2)
        metrics.max_complexity = max(complexities)


def analyze_source(path: str, source: str, thresholds: Thresholds | None = None) -> tuple[list[Finding], FileMetrics]:
    th = thresholds or Thresholds()
    lines = source.splitlines()
    loc = sum(1 for ln in lines if ln.strip() and not ln.strip().startswith("#"))
    metrics = FileMetrics(path=path, loc=loc)
    findings = _scan_secrets(path, lines)
    if path.endswith(".py"):
        try:
            tree = ast.parse(source)
        except SyntaxError as e:
            findings.append(Finding(path, e.lineno or 1, "syntax-error", "high", f"Syntax error: {e.msg}"))
        else:
            _analyze_tree(path, tree, th, findings, metrics)

    def suppressed(f: Finding) -> bool:
        return 0 < f.line <= len(lines) and "noqa: cra" in lines[f.line - 1]

    return [f for f in findings if not suppressed(f)], metrics
