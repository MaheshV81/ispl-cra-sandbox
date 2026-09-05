"""Token accounting and budget enforcement.

Three things were wrong before this module existed:

1. Cache tokens were silently dropped. The Anthropic API returns
   cache_creation_input_tokens and cache_read_input_tokens separately from
   input_tokens. Recording only input_tokens understates real usage on any
   cached prompt, so the audit figure was not the billed figure.

2. Nothing was deducted from anything. Tokens were recorded after the fact in
   three places and no budget was decremented. A misconfigured loop, a 3000-line
   diff, or a PR pushed forty times could spend without limit, and the first
   signal would have been the invoice.

3. Cost was never computed. Tokens are not money, and a governance conversation
   needs money.

What this module does NOT do: it is a ceiling, not a quota. It runs inside the
agent, so it can only stop the agent. A hard quota has to sit at the gateway
where the agent cannot reach it — see higress/ai-review-gateway.yaml. This is
the stopgap until that exists, and it should be described as such to anyone who
asks whether spend is controlled.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import policy


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0

    @property
    def total_input(self) -> int:
        """Every token the provider counts on the way in.

        Cache reads are usually cheaper and cache writes usually dearer than
        ordinary input, which is why they are priced separately below rather
        than folded in here.
        """
        return (self.input_tokens
                + self.cache_creation_input_tokens
                + self.cache_read_input_tokens)

    @property
    def total(self) -> int:
        return self.total_input + self.output_tokens

    def as_dict(self) -> dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_creation_input_tokens": self.cache_creation_input_tokens,
            "cache_read_input_tokens": self.cache_read_input_tokens,
            "total_tokens": self.total,
        }


def from_anthropic(resp: Any) -> Usage:
    u = getattr(resp, "usage", None)
    if u is None:
        return Usage()
    return Usage(
        input_tokens=getattr(u, "input_tokens", 0) or 0,
        output_tokens=getattr(u, "output_tokens", 0) or 0,
        cache_creation_input_tokens=getattr(u, "cache_creation_input_tokens", 0) or 0,
        cache_read_input_tokens=getattr(u, "cache_read_input_tokens", 0) or 0,
    )


def from_ollama(body: dict) -> Usage:
    return Usage(
        input_tokens=body.get("prompt_eval_count", 0) or 0,
        output_tokens=body.get("eval_count", 0) or 0,
    )


# --------------------------------------------------------------------------
# Cost
# --------------------------------------------------------------------------

def cost_usd(usage: Usage, model_id: str) -> float | None:
    """Cost for this call, or None if no rate is configured for the model.

    Returns None rather than guessing. A wrong cost figure in an audit record is
    worse than an absent one: absent prompts a question, wrong gets quoted in a
    budget meeting.
    """
    try:
        rates = policy.get("cost.rates_usd_per_million_tokens")
    except Exception:  # noqa: BLE001 - policy has no cost section
        return None

    rate = rates.get(model_id)
    if not rate:
        return None

    per_m = 1_000_000
    total = (
        usage.input_tokens * rate.get("input", 0)
        + usage.output_tokens * rate.get("output", 0)
        + usage.cache_creation_input_tokens * rate.get("cache_write", rate.get("input", 0))
        + usage.cache_read_input_tokens * rate.get("cache_read", rate.get("input", 0))
    ) / per_m
    return round(total, 6)


# --------------------------------------------------------------------------
# Ceilings — enforced before the call, not after
# --------------------------------------------------------------------------

def estimate_prompt_tokens(text: str) -> int:
    """Rough pre-call estimate. Roughly four characters per token for code and
    English prose.

    Deliberately crude and deliberately not conservative-by-luck: it is used
    only to refuse obviously oversized prompts before spending anything. The
    real figure comes back with the response.
    """
    return len(text) // 4


@dataclass
class BudgetDecision:
    allowed: bool
    reason: str = ""
    estimated_tokens: int = 0
    spent_tokens: int = 0
    ceiling: int = 0


def check_before_call(prompt_text: str, spent_on_pr: int) -> BudgetDecision:
    """Refuse the call if it would breach a configured ceiling.

    Two ceilings, both optional. If the policy has no cost section, this returns
    allowed and says so in the audit record — silent absence of a control is
    exactly what got us here.
    """
    estimated = estimate_prompt_tokens(prompt_text)

    try:
        per_run = int(policy.get("cost.max_tokens_per_run"))
        per_pr = int(policy.get("cost.max_tokens_per_pull_request"))
    except Exception:  # noqa: BLE001
        return BudgetDecision(True, "no cost ceilings configured", estimated, spent_on_pr, 0)

    if estimated > per_run:
        return BudgetDecision(
            False,
            f"estimated {estimated} prompt tokens exceeds cost.max_tokens_per_run "
            f"({per_run})",
            estimated, spent_on_pr, per_run,
        )

    if spent_on_pr + estimated > per_pr:
        return BudgetDecision(
            False,
            f"this pull request has already used {spent_on_pr} tokens; another "
            f"~{estimated} would exceed cost.max_tokens_per_pull_request ({per_pr})",
            estimated, spent_on_pr, per_pr,
        )

    return BudgetDecision(True, "", estimated, spent_on_pr, per_pr)


def format_ledger_line(usage: Usage, model_id: str, spent_before: int) -> str:
    """One human-readable line for the summary comment footer."""
    cost = cost_usd(usage, model_id)
    running = spent_before + usage.total
    parts = [
        f"{usage.total:,} tokens this run",
        f"{running:,} total on this pull request",
    ]
    if usage.cache_read_input_tokens:
        parts.append(f"{usage.cache_read_input_tokens:,} from cache")
    if cost is not None:
        parts.append(f"${cost:.4f}")
    return " · ".join(parts)
