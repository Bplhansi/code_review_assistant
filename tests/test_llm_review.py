import json

import pytest

from crassist.llm_review import OpenAICompatibleBackend, get_backend, parse_llm_response
from crassist.prompts import build_prompt


def test_parse_object_fenced_and_list():
    obj = {"findings": [{"line": 3, "severity": "Critical", "rule": "sqli", "message": "bad", "suggestion": "fix"}]}
    for text in (json.dumps(obj), f"Sure!\n```json\n{json.dumps(obj)}\n```", json.dumps(obj["findings"])):
        (f,) = parse_llm_response(text, "a.py")
        assert (f.line, f.severity, f.rule, f.source, f.suggestion) == (3, "high", "sqli", "llm", "fix")


def test_parse_garbage_and_bad_items():
    assert parse_llm_response("no json here", "a.py") == []
    assert parse_llm_response("{not json}", "a.py") == []
    assert parse_llm_response('{"findings": [{"line": "x"}, "str", {"message": "m", "line": 99}]}', "a.py", n_lines=10)[0].line == 10


def test_prompt_numbers_lines_and_focus():
    p = build_prompt("a.py", "x\ny", {2})
    assert "   1: x" in p and "   2: y" in p and "changed lines: 2" in p


class FakeSession:
    def __init__(self, text):
        self.text, self.calls = text, []

    def post(self, url, **kw):
        self.calls.append((url, kw))
        outer = self

        class R:
            def raise_for_status(self): pass
            def json(self): return {"choices": [{"message": {"content": outer.text}}]}
        return R()


def test_api_backend_request_shape():
    s = FakeSession('{"findings": [{"line": 1, "severity": "low", "rule": "r", "message": "m"}]}')
    b = OpenAICompatibleBackend(base_url="http://x/v1/", api_key="k", model="m1", session=s)
    (f,) = b.review("a.py", "print(1)")
    url, kw = s.calls[0]
    assert url == "http://x/v1/chat/completions" and kw["headers"]["Authorization"] == "Bearer k"
    assert kw["json"]["model"] == "m1" and kw["json"]["messages"][0]["role"] == "system"
    assert f.rule == "r"


def test_backend_selection(monkeypatch):
    monkeypatch.delenv("CRA_LLM_MODEL", raising=False)
    assert get_backend("none") is None
    with pytest.raises(RuntimeError):
        get_backend("api")
    with pytest.raises(ValueError):
        get_backend("bogus")
