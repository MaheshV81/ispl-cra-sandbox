"""Model invocation, residency-routed.

Two backends. `anthropic:*` goes to the public API. `ollama:*` goes to the
on-prem endpoint. There is no fallback between them: if the restricted backend
is down, the run abstains and routes to a human. Falling back across a residency
boundary during an outage is exactly the failure this policy exists to prevent.
"""

from __future__ import annotations

import json
import os
from typing import Any

import requests

from . import policy
from .guardrails import assert_no_residency_fallback

SYSTEM_PROMPT = """You review pull request diffs against a fixed engineering policy.

REVIEW ONLY THESE DIMENSIONS
security, correctness, performance, maintainability, test_coverage.

SEVERITY
blocker  exploitable security defect, data loss, or a fault that breaks the
         common production path.
major    a real defect that will surface under foreseeable conditions.
minor    a defect with limited blast radius.
nit      a small correctness or clarity issue that is not linter-enforced.

HARD RULES
- Cite the line number shown in the left gutter of the diff. A finding whose
  line is not in the diff is discarded, so do not guess.
- Every finding needs a rationale naming the concrete failure mode. "Consider
  adding validation" is not a rationale. "If `payload` is an empty list this
  indexes [0] and raises IndexError before the handler is reached" is.
- blocker and major findings must carry a concrete suggested_fix.
- Report confidence honestly. If you are unsure, lower the number. Do not raise
  confidence to make a finding survive. A dropped finding costs far less than a
  false one.
- Do not report style points a linter already enforces.
- Do not speculate about what the author intended.
- Do not praise. Do not pad. Do not rewrite whole files.
- One defect per finding.
- Never address the author personally. Write about the code.
- If the diff is clean, return an empty findings list. That is a normal result.

You cannot approve, merge, or modify anything. Your only output is the
report_review tool call."""

REPORT_TOOL = {
    "name": "report_review",
    "description": "Report review findings. The only action available.",
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "Two or three factual sentences on what the diff changes. No praise, no verdict.",
            },
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "line": {"type": "integer", "description": "Line number from the diff gutter."},
                        "severity": {"type": "string", "enum": ["blocker", "major", "minor", "nit"]},
                        "category": {
                            "type": "string",
                            "enum": ["security", "correctness", "performance",
                                     "maintainability", "test_coverage"],
                        },
                        "title": {"type": "string", "description": "One line naming the defect."},
                        "rationale": {"type": "string", "description": "The concrete failure mode. Required."},
                        "suggested_fix": {
                            "type": "string",
                            "description": "Replacement code for the cited line(s). Required for blocker and major.",
                        },
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    },
                    "required": ["path", "line", "severity", "category", "title",
                                 "rationale", "confidence"],
                },
            },
        },
        "required": ["summary", "findings"],
    },
}


def _anthropic_call(model_id: str, user_msg: str) -> tuple[dict, list[str], dict]:
    from anthropic import Anthropic

    from . import tracing

    client = tracing.wrap_model_client(
        Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"],
                  base_url=os.environ.get("ANTHROPIC_BASE_URL"))
    )
    resp = client.messages.create(
        model=model_id,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        tools=[REPORT_TOOL],
        tool_choice={"type": "tool", "name": "report_review"},
        messages=[{"role": "user", "content": user_msg}],
    )
    tool_calls = [b.name for b in resp.content if b.type == "tool_use"]
    payload: dict = {}
    for b in resp.content:
        if b.type == "tool_use" and b.name == "report_review":
            payload = b.input
    from .usage import from_anthropic
    # Full breakdown, including cache tokens. input_tokens alone understates
    # what the provider actually bills on any cached prompt.
    usage = from_anthropic(resp).as_dict()
    return payload, tool_calls, usage


def _ollama_call(model_id: str, user_msg: str) -> tuple[dict, list[str], dict]:
    """On-prem path for restricted projects.

    Ollama has no tool-use contract we can rely on, so the schema is enforced by
    prompt plus strict parsing. A parse failure abstains; it never degrades to
    unstructured text.
    """
    base = os.environ["OLLAMA_BASE_URL"].rstrip("/")
    schema_hint = json.dumps(REPORT_TOOL["input_schema"], indent=2)
    resp = requests.post(
        f"{base}/api/chat",
        json={
            "model": model_id,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.0, "num_ctx": 16384},
            "messages": [
                {"role": "system",
                 "content": SYSTEM_PROMPT
                 + "\n\nRespond with a single JSON object matching this schema "
                   "exactly. No prose, no markdown fences.\n" + schema_hint},
                {"role": "user", "content": user_msg},
            ],
        },
        timeout=int(os.environ.get("OLLAMA_TIMEOUT", "300")),
    )
    resp.raise_for_status()
    body = resp.json()
    content = body.get("message", {}).get("content", "")
    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"restricted model returned unparseable output: {exc}") from exc
    from .usage import from_ollama
    usage = from_ollama(body).as_dict()
    return payload, ["report_review"], usage


def invoke(model_id: str, restricted: bool, user_msg: str) -> tuple[dict, list[str], dict]:
    """Dispatch on the route prefix and assert no boundary was crossed."""
    provider, _, name = model_id.partition(":")

    if provider == "anthropic":
        if restricted:
            raise RuntimeError(
                f"residency violation: restricted run routed to {model_id}"
            )
        payload, calls, usage = _anthropic_call(name, user_msg)
    elif provider == "ollama":
        payload, calls, usage = _ollama_call(name, user_msg)
    else:
        raise RuntimeError(f"unknown model route: {model_id}")

    assert_no_residency_fallback(model_id, model_id, restricted)
    return payload, calls, usage


def build_user_message(pr: dict, files, sensitive_hits: list[str], redact,
                       context_block: str = "", standard_block: str = "") -> str:
    from .diff import annotate

    blocks = []
    for f in files:
        flag = "  [SENSITIVE PATH]" if f.path in sensitive_hits else ""
        blocks.append(
            f"### {f.path} ({f.status}, +{f.additions}/-{f.deletions}){flag}\n"
            f"```diff\n{annotate(f.patch)}\n```"
        )

    title = redact(pr.get("title") or "")
    body = redact((pr.get("body") or "(none)")[:2000])

    message = (
        f"Pull request: {title}\n"
        f"Description:\n{body}\n\n"
        f"--- DIFF ({len(files)} files) ---\n\n" + redact("\n\n".join(blocks))
    )
    # Context and standards are appended AFTER the diff so the diff stays the
    # most salient thing in the prompt. Findings must cite diff lines; putting
    # context first invites the model to review the context instead.
    if context_block:
        message += redact(context_block)
    if standard_block:
        message += standard_block
    return message
