"""Orchestrator.

Two subcommands, because the policy requires human approval for
post_review_comment:

  analyze   runs every guardrail stage and writes review.json. Posts nothing.
  publish   reads review.json and posts. Runs in a gated job.

Splitting them is what makes the approval real. If analyze could post, the
approval would be advisory.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone

from . import github as gh
from . import guardrails as gr
from . import model as ml
from . import policy
from . import render
from . import tracing
from .diff import build_index

STATE_RE = re.compile(r"<!-- ispl-cra-state: (.*?) -->", re.DOTALL)


def _load_event() -> dict:
    with open(os.environ["GITHUB_EVENT_PATH"]) as fh:
        return json.load(fh)


def _carry_forward(repo: str, pr_number: int, marker: str,
                   full_index: dict[str, set[int]]) -> list[dict]:
    """Unresolved blocker/major findings from earlier reviewed SHAs.

    Incremental re-review only looks at the newest commits, but the merge gate
    has to reflect the whole commit range headed for main. A finding raised three
    pushes ago whose line still exists in the PR diff is still unresolved and
    still counts toward the verdict.
    """
    carried: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    for c in gh._paginate(
        f"{gh.API}/repos/{repo}/issues/{pr_number}/comments"
    ):
        body = c.get("body") or ""
        if marker not in body:
            continue
        m = STATE_RE.search(body)
        if not m:
            continue
        try:
            prior = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        for f in prior.get("findings", []):
            key = (f["path"], f["line"], f["title"])
            if key in seen:
                continue
            if f["line"] not in full_index.get(f["path"], set()):
                continue  # the code it pointed at is gone; treat as resolved
            seen.add(key)
            f["carried_forward"] = True
            carried.append(f)
    return carried


def analyze() -> int:
    event = _load_event()
    pr = event.get("pull_request")
    if not pr:
        print("not a pull_request event")
        return 0

    repo = os.environ["GITHUB_REPOSITORY"]
    pr_number = pr["number"]
    head_sha = pr["head"]["sha"]
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    marker = policy.get("output.summary_comment.idempotency_marker")

    audit: dict = {
        "run_id": run_id,
        "policy_version": policy.get("policy_version"),
        "repo": repo,
        "pr_ref": f"{repo}#{pr_number}",
        "head_sha": head_sha,
        "trigger_event": os.environ.get("GITHUB_EVENT_NAME", "unknown"),
        "guardrail_blocks": [],
        "override_used": False,
        "false_positives_reported": 0,
        "human_decision": "pending",
    }

    def stop(reason: str, escalate: bool = False, verdict: str = "skipped") -> int:
        audit["guardrail_blocks"].append(reason)
        audit["verdict"] = verdict
        audit["findings_count"] = 0
        render.emit_audit(audit)
        _write_outcome({"action": "skip", "reason": reason, "escalate": escalate,
                        "head_sha": head_sha, "pr_number": pr_number, "repo": repo,
                        "run_id": run_id})
        print(f"::notice::{reason}")
        return 0

    # ---- stage 1a: scope admission ---------------------------------------
    prior_shas = gh.reviewed_shas(repo, pr_number, marker)
    runs, since = gh.run_history(repo, pr_number, marker)
    decision = gr.check_scope(pr, repo, gh.get_labels(pr), prior_shas, runs, since)
    if not decision.allowed:
        return stop(decision.reason, decision.escalate)

    # ---- fetch: incremental where possible -------------------------------
    full_files = gr.filter_paths(gh.fetch_changed_files(repo, pr_number))
    full_index = build_index(full_files)

    mode = policy.get("trigger.re_review_mode")
    files = full_files
    scope_note = "full pull request diff"
    if mode == "incremental_since_last_reviewed_sha" and prior_shas:
        last = sorted(prior_shas)[-1]
        try:
            incremental = gr.filter_paths(gh.compare_range(repo, last, head_sha))
            if incremental:
                files = incremental
                scope_note = f"incremental diff since {last[:8]}"
        except Exception as exc:  # noqa: BLE001 - degrade to full diff, never skip
            print(f"::warning::incremental compare failed ({exc}); using full diff")

    size = gr.check_diff_size(files)
    if not size.allowed:
        return stop(size.reason, size.escalate, verdict="out_of_scope")

    # ---- stage 1b: secret admission --------------------------------------
    secrets = gr.scan_for_secrets(files)
    if not secrets.allowed:
        audit["guardrail_blocks"].append(json.dumps(secrets.detail))
        return stop(secrets.reason, escalate=True, verdict="blocked_secret")

    sensitive_hits = gr.touches_sensitive(files)

    # ---- stage 2: residency routing --------------------------------------
    project = gh.detect_project(repo)
    model_id, restricted = gr.route_model(project)
    audit["project"] = project or "UNKNOWN"
    audit["model_used"] = model_id
    print(f"project={project or 'UNKNOWN'} restricted={restricted} model={model_id}")

    # Tracing is configured only after residency is known. A restricted run
    # never reaches an enabled tracer.
    tracing.configure(
        restricted=restricted, project=project, run_id=run_id, repo=repo,
        pr_ref=f"{repo}#{pr_number}", head_sha=head_sha,
        policy_version=str(policy.get("policy_version")), model_used=model_id,
    )
    if not tracing.enabled():
        print(f"::notice::tracing off — {tracing.disabled_reason()}")

    user_msg = ml.build_user_message(pr, files, sensitive_hits, gr.redact)
    audit["prompt_hash"] = render.prompt_hash(ml.SYSTEM_PROMPT, user_msg)

    try:
        payload, tool_calls, usage = ml.invoke(model_id, restricted, user_msg)
    except Exception as exc:  # noqa: BLE001
        # No fallback. A restricted backend outage abstains to a human.
        return stop(f"model call failed on {model_id}: {exc}", escalate=True,
                    verdict="abstained")

    audit["input_tokens"] = usage.get("input_tokens", 0)
    audit["output_tokens"] = usage.get("output_tokens", 0)

    # ---- stage 3: block write actions ------------------------------------
    writes = gr.assert_no_write_action(tool_calls)
    if not writes.allowed:
        audit["guardrail_blocks"].append(writes.reason)
        return stop(writes.reason, escalate=True, verdict="abstained")

    # ---- stage 4: validate, carry forward, compute verdict ---------------
    index = build_index(files)
    result = gr.validate_findings(payload.get("findings", []), index)

    carried = _carry_forward(repo, pr_number, marker, full_index)
    combined = result.findings + [f for f in carried
                                  if (f["path"], f["line"], f["title"]) not in
                                  {(x["path"], x["line"], x["title"]) for x in result.findings}]

    if result.abstained:
        audit["guardrail_blocks"].append(result.abstain_reason)
        return stop(result.abstain_reason, escalate=True, verdict="abstained")

    verdict = gr.compute_verdict(combined)
    escalations = gr.escalation_reasons(combined, sensitive_hits,
                                        validation_failed=False, verdict=verdict)

    not_reviewed = [f"Scope: {scope_note}."]
    if result.rejected:
        not_reviewed.append(
            f"{len(result.rejected)} model finding(s) discarded by evidence validation "
            f"(ungrounded line, missing rationale, missing fix, or confidence below "
            f"{policy.get('review.confidence_floor')})."
        )
    excluded = len(gh.fetch_changed_files(repo, pr_number)) - len(full_files)
    if excluded > 0:
        not_reviewed.append(f"{excluded} file(s) matched scope.excluded_paths.")
    if carried:
        not_reviewed.append(f"{len(carried)} unresolved finding(s) carried forward "
                            f"from earlier commits in this pull request.")

    summary = render.render_summary(
        verdict=verdict, summary_text=payload.get("summary", ""), findings=combined,
        not_reviewed=not_reviewed, model_used=model_id, run_id=run_id,
        head_sha=head_sha, escalations=escalations,
    )
    state = {"findings": [{k: f[k] for k in ("path", "line", "severity", "category", "title")}
                          for f in combined if f["severity"] in ("blocker", "major")]}
    summary += f"\n<!-- ispl-cra-state: {json.dumps(state)} -->"

    inline = render.select_inline(combined, index)

    audit["findings_count"] = len(combined)
    audit["verdict"] = verdict
    render.emit_audit(audit)

    tracing.record_outcome(
        verdict=verdict, findings_count=len(combined),
        rejected_count=len(result.rejected),
        input_tokens=audit["input_tokens"], output_tokens=audit["output_tokens"],
        guardrail_blocks=audit["guardrail_blocks"], escalations=escalations,
    )

    _write_outcome({
        "action": "post", "repo": repo, "pr_number": pr_number, "head_sha": head_sha,
        "run_id": run_id, "verdict": verdict, "summary_body": summary,
        "inline_comments": inline, "escalations": escalations,
        "check_conclusion": gr.check_conclusion(verdict, combined),
        "blocker_count": sum(1 for f in combined if f["severity"] == "blocker"),
        "major_count": sum(1 for f in combined if f["severity"] == "major"),
        "requires_human": bool(escalations)
        or "post_review_comment" in policy.get("authority.human_approval_required"),
    })

    print(f"verdict={verdict} findings={len(combined)} inline={len(inline)} "
          f"rejected={len(result.rejected)} escalate={bool(escalations)}")
    return 0


def _write_outcome(data: dict) -> None:
    os.makedirs("audit", exist_ok=True)
    with open("review.json", "w") as fh:
        json.dump(data, fh, indent=2)
    step_out = os.environ.get("GITHUB_OUTPUT")
    if step_out:
        with open(step_out, "a") as fh:
            fh.write(f"action={data.get('action')}\n")
            fh.write(f"verdict={data.get('verdict', 'skipped')}\n")
            fh.write(f"requires_human={str(data.get('requires_human', False)).lower()}\n")


def publish() -> int:
    """Post the already-approved review. Runs only after the environment gate."""
    with open("review.json") as fh:
        data = json.load(fh)

    if data.get("action") != "post":
        print(f"nothing to post: {data.get('reason', 'skipped')}")
        return 0

    repo, pr_number, head_sha = data["repo"], data["pr_number"], data["head_sha"]

    if policy.get("output.summary_comment.enabled"):
        gh.post_review(repo, pr_number, head_sha, data["summary_body"],
                       data["inline_comments"])

    check = policy.get("output.check_run")
    gh.post_check_run(
        repo, head_sha, check["name"], data["check_conclusion"],
        title=f"{data['verdict']} — {data['blocker_count']} blocker, "
              f"{data['major_count']} major",
        summary=data["summary_body"],
    )

    approver = os.environ.get("APPROVED_BY", "unknown")
    with open("audit/run.json") as fh:
        audit = json.load(fh)
    audit["human_decision"] = f"approved_post_by:{approver}"
    audit["published_at"] = datetime.now(timezone.utc).isoformat()
    with open("audit/run.json", "w") as fh:
        json.dump(audit, fh, indent=2, sort_keys=True)

    print(f"posted: verdict={data['verdict']} "
          f"inline={len(data['inline_comments'])} check={data['check_conclusion']}")
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "analyze"
    sys.exit(analyze() if cmd == "analyze" else publish())
