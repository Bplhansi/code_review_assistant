import json
import sys
from pathlib import Path

from crassist.cli import main
from crassist.dataset import format_example, load_jsonl, validate_dataset, validate_example

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "training"))
import build_sample_dataset  # noqa: E402
import lora_finetune  # noqa: E402


def test_sample_dataset_is_valid_and_in_sync():
    rows = load_jsonl(ROOT / "training" / "sample_dataset.jsonl")
    assert len(rows) >= 10 and validate_dataset(rows) == []
    assert rows == build_sample_dataset.build()
    assert any(not r["findings"] for r in rows), "dataset should include clean negative examples"


def test_validation_catches_problems():
    assert validate_example({"path": "a", "code": "x\n", "findings": [{"line": 5, "severity": "meh", "rule": "", "message": ""}]})
    assert validate_example({"path": "a"}) == ["missing 'code'", "missing 'findings'"]


def test_format_example_completion_is_parseable_json():
    prompt, completion = format_example(load_jsonl(ROOT / "training" / "sample_dataset.jsonl")[0])
    assert prompt.endswith("### Response:\n") and "   1: " in prompt
    assert json.loads(completion)["findings"][0]["rule"] == "mutable-default-arg"


def test_finetune_dry_run(capsys):
    assert lora_finetune.main(["--dry-run"]) == 0
    assert "train /" in capsys.readouterr().out


def test_cli_review_and_fail_on(tmp_path, capsys):
    f = tmp_path / "bad.py"
    f.write_text("eval('1')\n")
    assert main(["review", str(f), "--backend", "none"]) == 0
    assert main(["review", str(f), "--backend", "none", "--fail-on", "high", "--format", "json"]) == 1
    out = capsys.readouterr().out
    assert "dangerous-eval" in out


def test_cli_records_to_db(tmp_path):
    f = tmp_path / "ok.py"
    f.write_text("x = 1\n")
    db = tmp_path / "c.db"
    assert main(["review", str(tmp_path), "--backend", "none", "--db", str(db)]) == 0
    from crassist.metrics_store import MetricsStore
    assert MetricsStore(str(db)).summary()["reviews"] == 1
