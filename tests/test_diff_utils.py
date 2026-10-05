from crassist.diff_utils import added_lines, parse_unified_diff

PATCH = """@@ -1,3 +1,4 @@
 import os
+import sys
 x = 1
-y = 2
+y = 3
@@ -10,2 +11,3 @@ def f():
     a = 1
+    b = 2
     return a
"""


def test_added_lines():
    assert added_lines(PATCH) == {2, 4, 12}


def test_added_lines_empty():
    assert added_lines("") == set()


def test_no_newline_marker_ignored():
    assert added_lines("@@ -1 +1 @@\n-a\n+b\n\\ No newline at end of file\n") == {1}


def test_parse_unified_diff_multi_file():
    diff = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n" + PATCH +
            "diff --git a/b.py b/b.py\nnew file mode 100644\n--- /dev/null\n+++ b/b.py\n@@ -0,0 +1,2 @@\n+one\n+two\n"
            "diff --git a/gone.py b/gone.py\n--- a/gone.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n")
    parsed = parse_unified_diff(diff)
    assert parsed == {"a.py": {2, 4, 12}, "b.py": {1, 2}}
