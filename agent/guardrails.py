"""Guardrail stages.

  before_agent   scope admission + secret admission
  wrap_model     data residency routing
  after_model    block any write action the model attempts
  after_agent    validate every finding against the real diff, then compute the
                 verdict deterministically

Every stage fails closed. An Abstain result means: do not post, route to a human,
and record the reason in the audit log.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from . import policy
from .diff import ChangedFile, matches_any


@dataclass
class Decision:
    allowed: bool
    reason: str = ""
    escalate: bool = False
    detail: dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Stage 1a — scope admission
# --------------------------------------------------------------------------

# Read from policy, not hardcoded. Azure DevOps bot identities look nothing
# like GitHub's, so a hardcoded GitHub list means the bot-author skip silently
# never fires on Azure — a guardrail that passes without checking anything.
_FALLBACK_BOTS = {"dependabot", "dependabot[bot]", "renovate", "renovate[bot]",
                  "github-actions", "github-actions[bot]"}


def _bot_authors() -> set[str]:
    try:
        return {b.lower() for b in policy.get("scope.bot_authors")}
    except Exception:  # noqa: BLE001 - policy predates this key
        return _FALLBACK_BOTS


def check_scope(pr: dict, repo: str, labels: set[str], reviewed_shas: set[str],
                run_count: int, seconds_since_last_run: float | None) -> Decision:
    trig = policy.get("trigger")
    scope = policy.get("scope")

    # Scope is matched against the platform-qualified name, e.g.
    # "github:intertec/edmp-core" or "azure:intertec/EDMP/timesheet". A bare
    # pattern is treated as github for backward compatibility, so existing
    # policies keep working — but a new policy should qualify explicitly, or
    # permitting a GitHub repo silently permits an identically named Azure one.
    qualified = repo if ":" in repo else f"github:{repo}"
    patterns = [p if ":" in p else f"github:{p}" for p in scope["allowed_repos"]]
    if not matches_any(qualified, patterns):
        return Decision(False, f"repo {qualified} is outside scope.allowed_repos")

    if pr.get("draft"):
        return Decision(False, "pull request is in draft state")

    for label in ("no-ai-review", "wip"):
        if label in labels:
            return Decision(False, f"label present: {label}")

    author = (pr.get("user") or {}).get("login", "")
    if author.lower() in _bot_authors():
        return Decision(False, f"author is a bot: {author}")

    if pr["head"]["sha"] in reviewed_shas:
        return Decision(False, "head_sha already reviewed")

    limits = trig["rate_limits"]
    if run_count >= limits["max_runs_per_pull_request"]:
        return Decision(False,
                        f"rate limit: {run_count} runs already "
                        f"(max {limits['max_runs_per_pull_request']})")
    if seconds_since_last_run is not None and seconds_since_last_run < limits["cooldown_seconds"]:
        return Decision(False,
                        f"cooldown: {int(seconds_since_last_run)}s since last run "
                        f"(needs {limits['cooldown_seconds']}s)")

    return Decision(True)


def check_diff_size(files: list[ChangedFile]) -> Decision:
    scope = policy.get("scope")
    if len(files) == 0:
        return Decision(False, "every changed file matches scope.excluded_paths")
    if len(files) > scope["max_changed_files"]:
        return Decision(False,
                        f"{len(files)} changed files exceeds max_changed_files "
                        f"({scope['max_changed_files']})",
                        escalate=True)
    total = sum(f.changed_lines for f in files)
    if total > scope["max_diff_lines"]:
        return Decision(False,
                        f"{total} diff lines exceeds max_diff_lines "
                        f"({scope['max_diff_lines']})",
                        escalate=True)
    if total < scope["min_diff_lines"]:
        return Decision(False, "diff is empty after filtering")
    return Decision(True)


def filter_paths(files: list[ChangedFile]) -> list[ChangedFile]:
    excluded = policy.get("scope.excluded_paths")
    return [f for f in files if not matches_any(f.path, excluded)]


def touches_sensitive(files: list[ChangedFile]) -> list[str]:
    sensitive = policy.get("scope.sensitive_paths")
    return [f.path for f in files if matches_any(f.path, sensitive)]


# --------------------------------------------------------------------------
# Stage 1b — secret admission control
# --------------------------------------------------------------------------

def scan_for_secrets(files: list[ChangedFile]) -> Decision:
    """Refuse to send the diff to any model if it carries a live credential.

    This runs before the model call, not after. A secret that reaches the model
    has already left the trust boundary.
    """
    patterns = {name: re.compile(rx) for name, rx in policy.get("data.block_patterns").items()}
    hits: list[dict[str, str]] = []
    for f in files:
        for name, rx in patterns.items():
            if rx.search(f.patch):
                hits.append({"file": f.path, "pattern": name})
    if hits:
        return Decision(
            False,
            "secret admission control: credential pattern detected in diff",
            escalate=True,
            # Deliberately records the pattern name and file only. Never the match.
            detail={"hits": hits},
        )
    return Decision(True)


REDACTORS = {
    # The local part MUST start with an alphanumeric. Without that anchor the
    # diff's own "+" marker is a valid local part, so "+@app.post(...)" reads as
    # an email address and the decorator is redacted out of the code under
    # review. That silently corrupted every Python file using @module.method
    # decorators — Flask, FastAPI, pytest — and the model then reported the
    # mangled syntax as a defect. Found by the agent reviewing this repository.
    "email": (re.compile(
        r"\b[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}\b"),
        "[redacted-email]"),
    "ip": (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[redacted-ip]"),
    "api_key": (re.compile(r"(?i)\b(?:api[_-]?key|apikey|access[_-]?token)\b\s*[:=]\s*"
                           r"['\"]?[A-Za-z0-9\-._~+/]{12,}['\"]?"), "[redacted-api-key]"),
}


def redact(text: str) -> str:
    for field_name in policy.get("data.redact"):
        rx, replacement = REDACTORS[field_name]
        text = rx.sub(replacement, text)
    return text


# --------------------------------------------------------------------------
# Stage 2 — data residency routing
# --------------------------------------------------------------------------

def route_model(project: str | None) -> tuple[str, bool]:
    """Return (model_id, is_restricted).

    An unrecognised project is treated as restricted. That is the policy's
    unknown_project_behaviour and it is the whole point: a project we cannot
    identify must not have its source code sent to an external endpoint.
    """
    restricted_projects = set(policy.get("data.restricted_projects"))
    restricted_model = policy.get("data.restricted_model")

    if not project:
        # Unidentified project. unknown_project_behaviour decides, and it is
        # "restricted", so this is the fail-closed branch.
        if policy.get("data.unknown_project_behaviour") == "restricted":
            return restricted_model, True
        return policy.get("data.default_model"), False

    if project in restricted_projects:
        return restricted_model, True

    return policy.get("data.default_model"), False


def assert_no_residency_fallback(requested: str, actual: str, restricted: bool) -> None:
    """Crossing a residency boundary during a retry is a policy violation, not a
    degraded mode. Raise rather than continue."""
    if requested != actual:
        raise RuntimeError(
            f"residency violation: routed to {requested} but call executed on {actual}"
        )
    if restricted and actual.startswith("anthropic:"):
        raise RuntimeError(
            f"residency violation: restricted project routed to external model {actual}"
        )


# --------------------------------------------------------------------------
# Stage 3 — block write actions
# --------------------------------------------------------------------------

def assert_no_write_action(tool_calls: list[str]) -> Decision:
    forbidden = set(policy.get("authority.forbidden_actions"))
    permitted = set(policy.get("authority.permitted_tools"))
    attempted = [t for t in tool_calls if t in forbidden or t not in permitted | {"report_review"}]
    if attempted:
        return Decision(False,
                        f"model attempted non-permitted action(s): {', '.join(attempted)}",
                        escalate=True,
                        detail={"attempted": attempted})
    return Decision(True)


# --------------------------------------------------------------------------
# Stage 4 — finding validation and deterministic verdict
# --------------------------------------------------------------------------

@dataclass
class ValidationResult:
    findings: list[dict]
    rejected: list[dict]
    abstained: bool = False
    abstain_reason: str = ""


def validate_findings(raw: list[dict], index: dict[str, set[int]]) -> ValidationResult:
    rules = policy.get("review.evidence_rules")
    floor = policy.get("review.confidence_floor")
    max_findings = policy.get("review.max_findings")
    dimensions = set(policy.get("review.dimensions"))
    severities = set(policy.get("review.severities"))
    needs_fix = set(rules["require_suggested_fix_for"])

    kept: list[dict] = []
    rejected: list[dict] = []

    for f in raw:
        why = _reject_reason(f, index, rules, floor, dimensions, severities, needs_fix)
        if why:
            rejected.append({"finding": f, "reason": why})
        else:
            kept.append(f)

    kept.sort(key=lambda f: (policy.severity_rank(f["severity"]), f["path"], f["line"]))

    if len(kept) > max_findings:
        rejected += [{"finding": f, "reason": "exceeds review.max_findings"}
                     for f in kept[max_findings:]]
        kept = kept[:max_findings]

    # If the model produced findings but not one survived grounding, something is
    # wrong with the run. Abstain rather than post a clean bill of health.
    if raw and not kept:
        return ValidationResult(
            [], rejected, abstained=True,
            abstain_reason=f"all {len(raw)} findings failed evidence validation",
        )

    return ValidationResult(kept, rejected)


def _reject_reason(f: dict, index: dict[str, set[int]], rules: dict, floor: float,
                   dimensions: set, severities: set, needs_fix: set) -> str | None:
    for key in ("path", "line", "severity", "category", "title", "rationale", "confidence"):
        if key not in f:
            return f"missing required field: {key}"
    if f["severity"] not in severities:
        return f"severity not in policy: {f['severity']}"
    if f["category"] not in dimensions:
        return f"category not in review.dimensions: {f['category']}"
    if rules["file_must_exist_in_diff"] and f["path"] not in index:
        return "file does not exist in diff"
    if rules["line_must_exist_in_diff"] and f["line"] not in index.get(f["path"], set()):
        return f"line {f['line']} does not exist in diff for {f['path']}"
    if rules["require_rationale"] and not str(f.get("rationale", "")).strip():
        return "rationale is empty"
    try:
        confidence = float(f["confidence"])
    except (TypeError, ValueError):
        return "confidence is not numeric"
    if confidence < floor:
        return f"confidence {confidence:.2f} below floor {floor}"
    if f["severity"] in needs_fix and not str(f.get("suggested_fix", "")).strip():
        return f"{f['severity']} finding has no suggested_fix"
    return None


def compute_verdict(findings: list[dict]) -> str:
    """Deterministic. The model never chooses the verdict."""
    rules = policy.get("review.verdict_rules")
    blockers = sum(1 for f in findings if f["severity"] == "blocker")
    majors = sum(1 for f in findings if f["severity"] == "major")

    if blockers >= rules["request_changes_if_blockers"]:
        return "request_changes"
    if majors >= rules["request_changes_if_majors"]:
        return "request_changes"
    if majors >= rules["needs_discussion_if_majors"]:
        return "needs_discussion"
    return rules["otherwise"]


def escalation_reasons(findings: list[dict], sensitive_hits: list[str],
                       validation_failed: bool, verdict: str) -> list[str]:
    reasons: list[str] = []
    if any(f["severity"] == "blocker" for f in findings):
        reasons.append("finding of severity blocker")
    if any(f["category"] == "security" for f in findings):
        reasons.append("finding in category security")
    if sensitive_hits:
        reasons.append(f"changed file matches sensitive_paths: {', '.join(sensitive_hits[:5])}")
    if validation_failed:
        reasons.append("output validation failed")
    if verdict == "request_changes":
        reasons.append("verdict is request_changes")
    return reasons


def check_conclusion(verdict: str, findings: list[dict]) -> str:
    """Map verdict to a check-run conclusion for the *active* phase only.

    Phase 1 is advisory: this never returns "failure". That is deliberate and it
    is the policy. Do not add blocking here — change current_phase in the YAML.
    """
    ph = policy.phase()
    if not ph.get("check_blocking", False):
        return "neutral"

    blocking_sev = set(ph.get("blocking_severities", []))
    blocking_cat = ph.get("blocking_categories")

    for f in findings:
        if f["severity"] not in blocking_sev:
            continue
        if blocking_cat is not None and f["category"] not in set(blocking_cat):
            continue
        return "failure"
    return "success"
