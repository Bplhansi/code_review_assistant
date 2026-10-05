"""Generate sample_dataset.jsonl. Findings anchor to a marker substring so line numbers stay correct.

Usage: python training/build_sample_dataset.py
"""
import json
from pathlib import Path

# (path, code, [(marker, severity, rule, message, suggestion)])
EXAMPLES = [
    ("utils.py", """def add_item(item, bucket=[]):
    bucket.append(item)
    return bucket
""", [("bucket=[]", "medium", "mutable-default-arg",
       "The default list is created once and shared by every call, so items leak between calls.",
       "Use `bucket=None` and create a new list inside the function.")]),

    ("service.py", """def load_config(path):
    try:
        return json.load(open(path))
    except:
        return {}
""", [("except:", "medium", "bare-except",
       "Bare except hides real errors (including KeyboardInterrupt) and silently returns an empty config.",
       "Catch `OSError` and `json.JSONDecodeError`, and log the failure."),
      ("open(path)", "medium", "resource-leak",
       "The file handle is never closed explicitly.",
       "Use `with open(path) as fh:`.")]),

    ("calc.py", """def calculate(expression):
    return eval(expression)
""", [("eval(", "high", "dangerous-eval",
       "`eval` on caller-supplied text allows arbitrary code execution.",
       "Parse with `ast.literal_eval` or a dedicated expression parser.")]),

    ("db.py", """def find_user(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cur.fetchone()
""", [("cur.execute", "high", "sql-injection",
       "The query is built by concatenating user input, enabling SQL injection.",
       "Use a parameterised query: `cur.execute('... WHERE name = ?', (name,))`.")]),

    ("settings.py", """DB_HOST = "db.internal"
DB_PASSWORD = "hunter2hunter2"
DB_PORT = 5432
""", [("DB_PASSWORD", "high", "hardcoded-secret",
       "A database password is committed to source control.",
       "Read it from an environment variable or a secret manager and rotate the leaked value.")]),

    ("checks.py", """def is_missing(value):
    if value == None:
        return True
    return False
""", [("== None", "low", "none-comparison",
       "Equality comparison with None can be overridden by `__eq__`; also the if/return can be simplified.",
       "Use `return value is None`.")]),

    ("runner.py", """import subprocess

def run(branch):
    subprocess.run("git checkout " + branch, shell=True)
""", [("shell=True", "high", "shell-injection",
       "Interpolating `branch` into a shell command allows command injection.",
       "Use `subprocess.run(['git', 'checkout', branch], check=True)`.")]),

    ("fetch.py", """import requests

def get_status(url):
    return requests.get(url).status_code
""", [("requests.get", "low", "missing-timeout",
       "The request has no timeout and can block a worker indefinitely.",
       "Pass `timeout=10` and handle `requests.Timeout`.")]),

    ("dedupe.py", """def remove_duplicates(items):
    result = []
    for item in items:
        if item not in result:
            result.append(item)
    return result
""", [("if item not in result", "low", "quadratic-membership",
       "Membership tests on a list make this O(n^2).",
       "Track seen items in a set (or use `dict.fromkeys(items)` to keep order).")]),

    ("counter.py", """import threading

count = 0

def worker():
    global count
    for _ in range(1000):
        count += 1

threads = [threading.Thread(target=worker) for _ in range(4)]
""", [("count += 1", "medium", "race-condition",
       "`count += 1` is not atomic; concurrent threads will lose updates.",
       "Protect it with a `threading.Lock` or use a thread-safe counter.")]),

    ("orders.py", """def order_totals(session, customer_ids):
    totals = {}
    for cid in customer_ids:
        orders = session.query(Order).filter_by(customer_id=cid).all()
        totals[cid] = sum(o.amount for o in orders)
    return totals
""", [("session.query", "medium", "n-plus-one-query",
       "One database query is issued per customer inside the loop.",
       "Fetch all orders with a single `IN` query or a GROUP BY aggregate.")]),

    ("shapes.py", '''from dataclasses import dataclass


@dataclass
class Rectangle:
    width: float
    height: float

    def area(self) -> float:
        """Return the area of the rectangle."""
        return self.width * self.height
''', []),

    ("slugify.py", '''import re


def slugify(text: str) -> str:
    """Lowercase text and replace runs of non-alphanumerics with hyphens."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
''', []),
]


def build():
    rows = []
    for path, code, specs in EXAMPLES:
        lines = code.splitlines()
        findings = []
        for marker, sev, rule, msg, fix in specs:
            line = next(i for i, ln in enumerate(lines, 1) if marker in ln)
            findings.append({"line": line, "severity": sev, "rule": rule, "message": msg, "suggestion": fix})
        rows.append({"path": path, "code": code, "findings": findings})
    return rows


if __name__ == "__main__":
    out = Path(__file__).with_name("sample_dataset.jsonl")
    out.write_text("\n".join(json.dumps(r) for r in build()) + "\n", encoding="utf-8")
    print(f"wrote {len(EXAMPLES)} examples to {out}")
