"""LangSmith tracing, subject to the same policy as everything else.

Two constraints shape this module:

1. Residency. A trace payload contains the diff. Shipping it to LangSmith Cloud
   is the same boundary crossing as calling an external model, so tracing is
   hard-disabled for restricted projects. Routing the model call on-prem and
   then tracing the prompt to a US SaaS would defeat the control entirely.

2. audit.redact_code_in_logs. Even on unrestricted projects, inputs and outputs
   are withheld from the trace. What is sent is metadata: the audit fields, token
   counts, timings, and the prompt hash. That is enough to answer "what ran, when,
   under which policy, and what did it cost" without putting client source code
   in a third-party store.

If you need full prompt bodies in traces, that is a policy amendment to
redact_code_in_logs, not a change here.
"""

from __future__ import annotations

import os
from typing import Any, Callable

# Set at import, before any client is constructed and before any
# auto-instrumentation can fire. Client(hide_inputs=...) only masks traces sent
# through that one client instance; anything else instrumenting the model SDK
# uses its own client and ignores it. These variables are global and apply to
# every trace the process emits, which is the only version of this control that
# actually holds.
os.environ.setdefault("LANGSMITH_HIDE_INPUTS", "true")
os.environ.setdefault("LANGSMITH_HIDE_OUTPUTS", "true")

_ENABLED = False
_DISABLED_REASON = "not configured"
_CLIENT: Any = None
_METADATA: dict[str, Any] = {}
_ROOT_RUN_ID: str | None = None

# Env vars LangSmith reads. Cleared wholesale when tracing must not happen, so
# that a stray import cannot re-enable it.
_LS_VARS = ("LANGSMITH_TRACING", "LANGSMITH_API_KEY", "LANGSMITH_ENDPOINT",
            "LANGSMITH_PROJECT", "LANGCHAIN_TRACING_V2", "LANGCHAIN_API_KEY")


def configure(*, restricted: bool, project: str | None, run_id: str, repo: str,
              pr_ref: str, head_sha: str, policy_version: str,
              model_used: str) -> bool:
    """Decide whether this run may be traced, and attach audit metadata."""
    global _ENABLED, _DISABLED_REASON, _CLIENT, _METADATA

    if restricted:
        _hard_disable()
        _DISABLED_REASON = (
            f"residency: project {project or 'UNKNOWN'} is restricted; "
            "traces would leave the on-prem boundary"
        )
        print(f"::notice::tracing disabled — {_DISABLED_REASON}")
        return False

    if not os.environ.get("LANGSMITH_API_KEY"):
        _DISABLED_REASON = "LANGSMITH_API_KEY not set"
        return False

    try:
        from langsmith import Client
    except ImportError:
        _DISABLED_REASON = "langsmith package not installed"
        return False

    _CLIENT = Client(
        api_key=os.environ["LANGSMITH_API_KEY"],
        api_url=os.environ.get("LANGSMITH_ENDPOINT", "https://api.smith.langchain.com"),
        # The whole point. Nothing that could contain source leaves the runner.
        hide_inputs=True,
        hide_outputs=True,
    )
    os.environ["LANGSMITH_TRACING"] = "true"
    os.environ["LANGSMITH_HIDE_INPUTS"] = "true"
    os.environ["LANGSMITH_HIDE_OUTPUTS"] = "true"
    os.environ.setdefault("LANGSMITH_PROJECT", "ispl-cra")

    # Fail closed. If the masking variables are not set at this point, do not
    # trace at all: a trace carrying the diff is worse than no trace.
    if (os.environ.get("LANGSMITH_HIDE_INPUTS") != "true"
            or os.environ.get("LANGSMITH_HIDE_OUTPUTS") != "true"):
        _hard_disable()
        _DISABLED_REASON = "input/output masking could not be enforced"
        print(f"::warning::tracing disabled — {_DISABLED_REASON}")
        return False

    _METADATA = {
        "run_id": run_id,
        "policy_version": policy_version,
        "repo": repo,
        "project": project or "UNKNOWN",
        "pr_ref": pr_ref,
        "head_sha": head_sha,
        "model_used": model_used,
        "residency": "unrestricted",
    }
    _ENABLED = True
    return True


def _hard_disable() -> None:
    global _ENABLED, _CLIENT
    _ENABLED = False
    _CLIENT = None
    for var in _LS_VARS:
        os.environ.pop(var, None)
    os.environ["LANGSMITH_TRACING"] = "false"
    # Left set deliberately. If anything re-enables tracing later in the
    # process, it must still not be able to ship inputs or outputs.
    os.environ["LANGSMITH_HIDE_INPUTS"] = "true"
    os.environ["LANGSMITH_HIDE_OUTPUTS"] = "true"


def enabled() -> bool:
    return _ENABLED


def disabled_reason() -> str:
    return _DISABLED_REASON


def metadata() -> dict[str, Any]:
    return dict(_METADATA)


def span(name: str, run_type: str = "chain") -> Callable:
    """Decorator. Becomes a no-op when tracing is off, including on every
    restricted run, so call sites need no conditionals."""
    def decorator(fn: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            if not _ENABLED:
                return fn(*args, **kwargs)
            from langsmith import traceable
            from langsmith.run_helpers import get_current_run_tree

            def inner(*a, **kw):
                global _ROOT_RUN_ID
                tree = get_current_run_tree()
                if tree is not None and _ROOT_RUN_ID is None:
                    _ROOT_RUN_ID = str(tree.id)
                return fn(*a, **kw)

            inner.__name__ = getattr(fn, "__name__", name)
            traced = traceable(
                name=name, run_type=run_type, client=_CLIENT,
                metadata=_METADATA,
            )(inner)
            return traced(*args, **kwargs)
        wrapper.__name__ = getattr(fn, "__name__", name)
        wrapper.__doc__ = getattr(fn, "__doc__", None)
        return wrapper
    return decorator


def wrap_model_client(client: Any) -> Any:
    """Wrap the Anthropic SDK client so token usage lands in the trace.

    Returns the client untouched when tracing is off.
    """
    if not _ENABLED:
        return client
    try:
        from langsmith.wrappers import wrap_anthropic
        return wrap_anthropic(client)
    except AttributeError as exc:
        # .messages is patched before it reaches for .completions and raises,
        # so the client handed back is instrumented. Do not "clean this up".
        print(f"::debug::partial anthropic wrap ({exc})")
        return client
    except Exception as exc:
        print(f"::warning::could not wrap model client: {exc}")
        return client


def record_outcome(*, verdict: str, findings_count: int, rejected_count: int,
                   input_tokens: int, output_tokens: int,
                   guardrail_blocks: list[str], escalations: list[str]) -> None:
    """Attach run-level results as feedback on the trace.

    Feedback is what makes a trace queryable later — "show me every run that
    abstained on a secret block" is a filter, not a grep. It also auto-upgrades
    the trace to extended retention, which is what gets you past the 14-day
    default and into range of the 365-day audit clause.
    """
    if not _ENABLED or _CLIENT is None:
        return
    if _ROOT_RUN_ID is None:
        return
    run_id = _METADATA.get("run_id")
    try:
        for key, value in (
            ("verdict", verdict),
            ("findings_count", findings_count),
            ("rejected_findings", rejected_count),
            ("guardrail_blocked", bool(guardrail_blocks)),
            ("escalated", bool(escalations)),
        ):
            _CLIENT.create_feedback(
                run_id=_ROOT_RUN_ID, key=key,
                score=value if isinstance(value, (int, float, bool)) else None,
                value=value if isinstance(value, str) else None,
                comment=f"ispl-cra run {run_id}",
            )
    except Exception as exc:  # noqa: BLE001
        # Tracing must never fail the review. Observability is not a gate.
        print(f"::warning::could not record trace feedback: {exc}")
