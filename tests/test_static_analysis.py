from crassist.static_analysis import Thresholds, analyze_source, cyclomatic_complexity


def rules(src, path="m.py", **kw):
    findings, _ = analyze_source(path, src, Thresholds(**kw) if kw else None)
    return {f.rule for f in findings}


def test_mutable_default():
    assert "mutable-default-arg" in rules("def f(x, y=[]):\n    return y\n")
    assert "mutable-default-arg" not in rules("def f(x, y=None):\n    return y\n")


def test_bare_except_and_swallow():
    r = rules("try:\n    pass\nexcept:\n    pass\n")
    assert {"bare-except", "swallowed-exception"} <= r


def test_dangerous_calls():
    src = "import os, subprocess\neval('1')\nos.system('ls')\nsubprocess.run('ls', shell=True)\n"
    findings, _ = analyze_source("m.py", src)
    assert [f.rule for f in findings].count("shell-injection") == 2
    assert "dangerous-eval" in {f.rule for f in findings}


def test_sql_injection_detected_only_for_dynamic_strings():
    assert "sql-injection" in rules("def f(c, n):\n    c.execute(f'SELECT {n}')\n")
    assert "sql-injection" in rules("def f(c, n):\n    c.execute('SELECT ' + n)\n")
    assert "sql-injection" not in rules("def f(c, n):\n    c.execute('SELECT ?', (n,))\n")


def test_secret_scan_ignores_placeholders():
    assert "hardcoded-secret" in rules('PASSWORD = "s3cr3t-value-123"\n', path="a.txt")
    assert "hardcoded-secret" not in rules('PASSWORD = "changeme-please"\n', path="a.txt")


def test_complexity_and_thresholds():
    body = "\n".join(f"    if x == {i}:\n        return {i}" for i in range(12))
    src = f"def f(x):\n{body}\n    return -1\n"
    assert "high-complexity" in rules(src)
    assert "high-complexity" not in rules(src, max_complexity=50)


def test_cyclomatic_complexity_counts_boolops():
    import ast
    fn = ast.parse("def f(a, b):\n    return a and b or (a if b else 1)\n").body[0]
    assert cyclomatic_complexity(fn) == 1 + 2 + 1


def test_unused_import_and_none_compare_and_timeout():
    r = rules("import os\nimport requests\nx = 1\nif x == None:\n    requests.get('u')\n")
    assert {"unused-import", "none-comparison", "missing-timeout"} <= r
    assert "unused-import" not in rules("import os\nprint(os.name)\n")


def test_syntax_error_reported():
    findings, _ = analyze_source("bad.py", "def f(:\n")
    assert findings[0].rule == "syntax-error" and findings[0].severity == "high"


def test_noqa_suppression():
    assert "dangerous-eval" not in rules("eval('1')  # noqa: cra\n")


def test_metrics():
    _, m = analyze_source("m.py", "def a():\n    return 1\n\ndef b(x):\n    if x:\n        return 1\n    return 2\n")
    assert m.functions == 2 and m.max_complexity == 2 and m.loc == 6
