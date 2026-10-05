"""LLM review backends: any OpenAI-compatible API, or a local LoRA-fine-tuned model."""
from __future__ import annotations

import json
import os
import re
from typing import Protocol

import requests

from .models import Finding, normalize_severity
from .prompts import SYSTEM, build_prompt, render_plain_prompt


class LLMBackend(Protocol):
    def review(self, path: str, code: str, changed_lines: set[int] | None = None) -> list[Finding]: ...


def parse_llm_response(text: str, path: str, n_lines: int | None = None) -> list[Finding]:
    """Tolerant parser: accepts {"findings": [...]}, a bare list, and fenced/chatty output."""
    m = re.search(r"\{.*\}|\[.*\]", text or "", re.S)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return []
    items = data.get("findings", []) if isinstance(data, dict) else data
    out = []
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict) or not it.get("message"):
            continue
        try:
            line = max(1, int(it.get("line", 1)))
        except (TypeError, ValueError):
            line = 1
        if n_lines:
            line = min(line, n_lines)
        out.append(Finding(path, line, str(it.get("rule") or "llm-review"), normalize_severity(it.get("severity")),
                           str(it["message"]), source="llm", suggestion=str(it.get("suggestion") or "")))
    return out


class OpenAICompatibleBackend:
    """Any server exposing the OpenAI-style `/chat/completions` API (hosted or local).

    Configure with CRA_LLM_BASE_URL, CRA_LLM_MODEL and (if required) CRA_LLM_API_KEY.
    Examples: https://api.openai.com/v1, http://localhost:11434/v1 (Ollama), http://localhost:8000/v1 (vLLM).
    """

    def __init__(self, base_url: str | None = None, api_key: str | None = None, model: str | None = None,
                 session: requests.Session | None = None, max_tokens: int = 1500, temperature: float = 0.0):
        self.base_url = (base_url or os.environ.get("CRA_LLM_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("CRA_LLM_API_KEY", "")
        self.model = model or os.environ.get("CRA_LLM_MODEL", "")
        if not self.model:
            raise RuntimeError("CRA_LLM_MODEL is not set")
        self.session = session or requests.Session()
        self.max_tokens = max_tokens
        self.temperature = temperature

    def review(self, path, code, changed_lines=None):
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        resp = self.session.post(
            f"{self.base_url}/chat/completions", headers=headers,
            json={"model": self.model, "max_tokens": self.max_tokens, "temperature": self.temperature,
                  "messages": [{"role": "system", "content": SYSTEM},
                               {"role": "user", "content": build_prompt(path, code, changed_lines)}]},
            timeout=90,
        )
        resp.raise_for_status()
        text = resp.json()["choices"][0]["message"].get("content") or ""
        return parse_llm_response(text, path, len(code.splitlines()))


class LocalLoRABackend:
    """Runs a base model with a LoRA adapter produced by `training/lora_finetune.py`."""

    def __init__(self, base_model: str | None = None, adapter_dir: str | None = None, max_new_tokens: int = 512):
        import torch
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer

        base_model = base_model or os.environ.get("CRA_BASE_MODEL", "Qwen/Qwen2.5-Coder-0.5B-Instruct")
        adapter_dir = adapter_dir or os.environ.get("CRA_ADAPTER_DIR", "training/out/adapter")
        self._torch = torch
        self.tok = AutoTokenizer.from_pretrained(base_model)
        model = AutoModelForCausalLM.from_pretrained(base_model, torch_dtype="auto")
        self.model = PeftModel.from_pretrained(model, adapter_dir).eval()
        self.max_new_tokens = max_new_tokens

    def review(self, path, code, changed_lines=None):
        prompt = render_plain_prompt(path, code, changed_lines)
        inputs = self.tok(prompt, return_tensors="pt").to(self.model.device)
        with self._torch.no_grad():
            out = self.model.generate(**inputs, max_new_tokens=self.max_new_tokens, do_sample=False,
                                      pad_token_id=self.tok.eos_token_id)
        text = self.tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)
        return parse_llm_response(text, path, len(code.splitlines()))


def get_backend(name: str | None) -> LLMBackend | None:
    name = (name or "none").lower()
    if name in ("none", "off", ""):
        return None
    if name in ("api", "openai"):
        return OpenAICompatibleBackend()
    if name == "local":
        return LocalLoRABackend()
    raise ValueError(f"unknown backend {name!r} (use none|api|local)")
