# Code Review Assistant

A small tool that reviews code in two passes: a static analyzer that finds common problems, and an optional LLM pass for things a rule can't catch. It can comment on GitHub pull requests, keeps a history of results in SQLite, and has a web dashboard. There is also a script for fine-tuning a small local model with LoRA.

## Setup

```bash
pip install -e ".[dev]"
pytest
```

## Usage

Static analysis only (no keys needed):

```bash
crassist review src/ --fail-on high
```

Add an LLM pass. Any server that speaks the OpenAI `/chat/completions` format works (OpenAI, Ollama, vLLM, LM Studio, OpenRouter...):

```bash
export CRA_LLM_BASE_URL=http://localhost:11434/v1
export CRA_LLM_MODEL=qwen2.5-coder:7b
crassist review src/ --backend api
```

Other options: `--format text|json|markdown`, `--diff-base origin/main` to review only changed lines, `--db crassist.db` to save results for the dashboard.

Dashboard (with demo data): `crassist serve --demo`, then open http://127.0.0.1:8000.

## Static checks

Python files: mutable default arguments, bare or swallowed `except`, `eval`/`exec`, `os.system` and `shell=True`, SQL built with string formatting, unsafe `pickle` and `yaml.load`, weak hashes, requests without a timeout, `== None`, unused imports, long functions, high cyclomatic complexity, too many arguments, missing docstrings, syntax errors. Every text file gets a hard-coded secret scan. Add `# noqa: cra` to a line to silence it.

The score is 0 to 100, based on severity-weighted findings per 100 lines.

## GitHub pull requests

1. Make a token with pull request write and contents read access, and pick a webhook secret.
2. Start the server: `GITHUB_TOKEN=... GITHUB_WEBHOOK_SECRET=... CRA_BACKEND=api crassist serve --host 0.0.0.0`
3. Add a webhook to your repo pointing at `/webhook/github` (JSON, same secret, "Pull requests" events).

It reviews only the lines a PR adds, posts one review with inline comments (up to 30) and a summary, and saves the result. It never requests changes. Unsigned requests are rejected. For local testing only, `CRA_ALLOW_UNSIGNED=1` skips the check.

Without a server: `crassist pr owner/repo 123 --dry-run`.

## Fine-tuning

```bash
pip install -e ".[train]"
python training/lora_finetune.py --dry-run     # check the data, no GPU needed
python training/lora_finetune.py --epochs 5    # adapter goes to training/out/adapter
CRA_ADAPTER_DIR=training/out/adapter crassist review src/ --backend local
```

Training data is JSONL, one example per line:

```json
{"path": "x.py", "code": "...", "findings": [{"line": 3, "severity": "high", "rule": "sql-injection", "message": "...", "suggestion": "..."}]}
```

Include some clean files with an empty `findings` list so the model learns when to say nothing. `training/build_sample_dataset.py` regenerates the 13-example sample file. That is only enough to test the pipeline; a model worth using needs far more data.

## Layout

- `src/crassist/` - the package (analysis, LLM backends, reviewer, GitHub, store, API, CLI, dashboard page)
- `training/` - dataset builder and LoRA script
- `tests/` - pytest suite; GitHub and LLM calls are faked, so no network is needed

## Notes

- Deep checks are Python-only. Other languages get the secret scan and the LLM pass.
- Code goes to whatever LLM server you configure. Use a local one for private code.
- The dashboard has no login. Keep it behind a proxy or VPN.
- The LLM and GitHub HTTP code is tested with fakes only, not against live services.
