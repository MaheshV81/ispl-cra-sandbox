"""Rendering and audit.

The summary comment sections and their order are fixed by output.summary_comment
in the policy. Do not reorder them here.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

from . import policy

ICON = {"blocker": "🔴", "major": "🟠", "minor": "🟡", "nit": "🔵"}
VERDICT_LABEL = {
    "request_changes": "Request changes",
    "needs_discussion": "Needs discussion",
    "comment_only": "Comment only",
    "abstained": "Abstained — routed to a human",
}


def render_summary(*, verdict: str, summary_text: str, findings: list[dict],
                   not_reviewed: list[str], model_used: str, run_id: str,
                   head_sha: str, escalations: list[str]) -> str:
    marker = policy.get("output.summary_comment.idempotency_marker")
    phase = policy.phase()
    blockers = [f for f in findings if f["severity"] == "blocker"]
    majors = [f for f in findings if f["severity"] == "major"]
    lows = [f for f in findings if f["severity"] in ("minor", "nit")]

    out: list[str] = [marker, "", "## AI Review"]

    # 1. verdict and finding counts
    out += [
        f"**Verdict: {VERDICT_LABEL.get(verdict, verdict)}** — "
        f"{len(blockers)} blocker, {len(majors)} major, "
        f"{len([f for f in findings if f['severity'] == 'minor'])} minor, "
        f"{len([f for f in findings if f['severity'] == 'nit'])} nit.",
        "",
    ]
    if not phase.get("check_blocking", False):
        out += [f"_Phase {phase['number']} ({phase['name']}): this check is advisory "
                f"and does not gate merge._", ""]

    if escalations:
        out += ["> **Routed to a human reviewer.** " + "; ".join(escalations), ""]

    if summary_text.strip():
        out += [summary_text.strip(), ""]

    # 2. blocker and major findings as a table
    if blockers or majors:
        out += ["### Blocking-severity findings", "",
                "| Severity | File | Line | Category | Defect | Confidence |",
                "|---|---|---|---|---|---|"]
        for f in blockers + majors:
            out.append(
                f"| {ICON[f['severity']]} {f['severity']} | `{f['path']}` | {f['line']} "
                f"| {f['category']} | {f['title']} | {float(f['confidence']):.2f} |"
            )
        out.append("")

    # 3. minor and nit findings inside a collapsed block
    if lows:
        out += [f"<details><summary>Minor and nit findings ({len(lows)})</summary>", "",
                "| Severity | File | Line | Category | Defect |", "|---|---|---|---|---|"]
        for f in lows:
            out.append(
                f"| {ICON[f['severity']]} {f['severity']} | `{f['path']}` | {f['line']} "
                f"| {f['category']} | {f['title']} |"
            )
        out += ["", "</details>", ""]

    # 4. what was not reviewed and why
    out += ["<details><summary>Not reviewed</summary>", ""]
    if not_reviewed:
        out += [f"- {item}" for item in not_reviewed]
    else:
        out.append("- Nothing excluded.")
    out += ["", "</details>", ""]

    # 5. footer
    out += [
        "---",
        f"Policy `{policy.get('policy_id')}` v{policy.get('policy_version')} · "
        f"model `{model_used}` · run `{run_id}`",
        "",
        f"React 👍/👎 on a finding, or reply "
        f"`{policy.get('output.feedback_capture.reply_command')}` to flag a false positive.",
        "",
        f"<!-- reviewed_sha: {head_sha} -->",
    ]
    return "\n".join(out)


def render_inline(f: dict) -> str:
    marker = policy.get("output.summary_comment.idempotency_marker")
    parts = [
        f"{ICON[f['severity']]} **{f['severity']} · {f['category']}** — {f['title']}",
        "",
        f["rationale"],
    ]
    if f.get("suggested_fix") and policy.get("output.inline_comments.use_github_suggestion_blocks"):
        parts += ["", "```suggestion", f["suggested_fix"].rstrip(), "```"]
    parts += ["", f"<sub>confidence {float(f['confidence']):.2f}</sub>", "", marker]
    return "\n".join(parts)


def select_inline(findings: list[dict], index: dict[str, set[int]]) -> list[dict]:
    cfg = policy.get("output.inline_comments")
    if not cfg["enabled"]:
        return []
    allowed = set(cfg["severities"])
    out: list[dict] = []
    for f in findings:
        if f["severity"] not in allowed:
            continue
        if f["line"] not in index.get(f["path"], set()):
            continue
        out.append({"path": f["path"], "line": f["line"], "side": "RIGHT",
                    "body": render_inline(f)})
        if len(out) >= cfg["max_per_pull_request"]:
            break
    return out


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------

def emit_audit(record: dict, path: str = "audit/run.json") -> dict:
    """Write the audit record with exactly the fields the policy lists.

    redact_code_in_logs is honoured by construction: no field in the schema
    carries diff content, and this function refuses to write one that does.
    """
    fields = policy.get("audit.log_fields")
    complete = {k: record.get(k) for k in fields}
    complete["logged_at"] = datetime.now(timezone.utc).isoformat()
    complete["retention_days"] = policy.get("audit.retention_days")

    if policy.get("audit.redact_code_in_logs"):
        for k, v in complete.items():
            if isinstance(v, str) and ("```" in v or "\n+" in v or "\n-" in v):
                complete[k] = "[code redacted from audit log]"

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(complete, fh, indent=2, sort_keys=True)
    return complete


def prompt_hash(system: str, user: str) -> str:
    return hashlib.sha256(f"{system}\x00{user}".encode()).hexdigest()[:32]
