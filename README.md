# ISPL-CRA-001 — Code Review Agent

Enforces `policy/review_policy.yaml`. The YAML is authoritative; the code only
implements it. Changing behaviour means changing the policy, not the Python.

```
policy/review_policy.yaml        authoritative policy
agent/policy.py                  loader, fails closed on missing keys
agent/diff.py                    diff parsing, glob matching, evidence index
agent/guardrails.py              the four stages
agent/model.py                   residency-routed model call
agent/github.py                  API access, read-only except post_review_comment
agent/render.py                  comment rendering + audit emission
agent/main.py                    analyze / publish orchestration
.github/workflows/ai-review.yml  two-job workflow with the approval gate
higress/ai-review-gateway.yaml   platform-level governance
```

## Three things that changed from what we built earlier

**1. Nothing blocks merge.** `branch_protection.current_phase: 1` is Advisory,
`check_blocking: false`. You originally asked for "block merge on critical
findings" — the policy overrides that, and the check run is named
"AI Review (advisory)" to match. `check_conclusion()` returns `neutral` in phase
1 and there is no code path that returns `failure`. Move to phase 2 by editing
`current_phase` in the YAML, once you clear the stated exit criteria (precision
above 0.80 on blocker/major over 200 PRs). Do not add blocking to the Python.

**2. The cost tiering is gone.** You asked for whichever model is cheaper per
PR. `data.default_model` pins `claude-sonnet-4-6`, so the Haiku-first routing
I built is dead. Model choice is now a residency decision, not a cost decision.
Cost control moved to the gateway as a hard token quota. That is the right place
for it, but it does mean per-PR spend goes up.

**3. The agent cannot post on its own.**
`authority.human_approval_required: [post_review_comment]` means every comment
needs a human to approve it. The workflow implements this as two jobs, where
`publish` sits behind a GitHub Environment with required reviewers and holds the
only write permission in the file. See the open question below — this is the one
I would push back on.

## Guardrail stages

| Stage | Where | Enforces |
|---|---|---|
| Before agent | `check_scope`, `check_diff_size`, `filter_paths` | repo allowlist, draft, labels, bot authors, already-reviewed SHA, rate limits, file/line caps, excluded paths |
| Before agent | `scan_for_secrets` | `data.block_patterns`. A diff carrying a credential never reaches any model — the check runs *before* the call, because a secret that reaches the model has already left the trust boundary |
| Wrap model | `route_model`, `invoke` | residency. Unknown project routes to on-prem. No fallback across the boundary; a restricted outage abstains |
| After model | `assert_no_write_action` | any tool outside `permitted_tools`. The GitHub client also has no merge/approve/push method at all — capability absence beats capability checking |
| After agent | `validate_findings`, `compute_verdict` | every evidence rule; verdict computed from `verdict_rules` arithmetic, never chosen by the model |

## Compliance matrix

| Policy clause | Implementation |
|---|---|
| `trigger.skip_when` (6 conditions) | `guardrails.check_scope` + `check_diff_size` |
| `trigger.manual_command: /ai-review` | `issue_comment` trigger, PR context materialised in the workflow |
| `trigger.re_review_mode` | `compare_range` since last reviewed SHA, with full-diff fallback |
| `trigger.rate_limits` | run/cooldown counted from prior marker comments; `concurrency` group |
| `scope.allowed_repos` | glob match, run refuses outside it |
| `scope.excluded_paths` / `sensitive_paths` | `matches_any` with `**` semantics |
| `data.*_model`, `unknown_project_behaviour` | `route_model`, unknown → restricted |
| `data.redact` | `redact()` before the prompt is built; gateway masking behind it |
| `data.block_patterns` | `scan_for_secrets`, pre-call |
| `authority.forbidden_actions` | `assert_no_write_action` + no such methods exist |
| `authority.human_approval_required` | `publish` job gated on the `ai-review-publish` environment |
| `authority.escalate_to_human_when` | `escalation_reasons`, surfaced in the comment and audit |
| `review.evidence_rules` | `_reject_reason`, all five rules |
| `review.confidence_floor` | rejection below 0.70 |
| `review.max_findings` | truncation after severity sort |
| `review.verdict_rules` | `compute_verdict`, pure arithmetic |
| `review.prohibited_output` | system prompt bans praise, linter nits, whole-file rewrites, intent speculation |
| `output.summary_comment.sections` | `render_summary`, in the listed order |
| `output.inline_comments` | blocker/major only, cap 10, suggestion blocks |
| `output.check_run` | verdict + blocker_count + major_count |
| `branch_protection.invariants` | review posted as `COMMENT`, never `REQUEST_CHANGES`, so it can never satisfy a required approval |
| `audit.log_fields` | `emit_audit` writes exactly those keys |
| `audit.redact_code_in_logs` | schema carries no diff content; `emit_audit` strips anything that looks like code |

## Setup

1. Copy `agent/`, `policy/`, `requirements.txt`, and the workflow into each
   in-scope repo (`intertec/edmp-*`, `intertec/qa-automation-*`).
2. Create the **`ai-review-publish` environment** (Settings → Environments) with
   required reviewers set to your tech leads and engineering managers. Without
   this, the publish job runs unattended and the human-approval clause is not met.
3. Repo variables: `HIGRESS_GATEWAY_URL`, `OLLAMA_BASE_URL`,
   `AI_REVIEW_RUNNER` (self-hosted label, restricted repos only),
   `REVIEW_PROJECT` (only if the code is not discoverable from the repo).
4. Repo secrets: `HIGRESS_CONSUMER_KEY` — the per-consumer key from the gateway,
   not a raw Anthropic key. Routing the agent straight at the Anthropic API
   bypasses residency, quota, masking, and observability in one step.
5. Branch protection on `main`: require at least one human approval. Do **not**
   add `AI Review (advisory)` as a required check while in phase 1.

## Open questions

**The approval gate is the sharp edge.** As written, every PR review waits for a
tech lead to click approve before a single comment appears. On a busy repo that
either becomes a bottleneck or becomes rubber-stamping, and rubber-stamping is
worse than no gate because it produces an audit trail that says a human reviewed
something they did not. Two alternatives worth taking to the policy owner:

- Gate only on `escalate_to_human_when` conditions (blocker, security, sensitive
  path, validation failure). Everything else posts unattended. `review.json`
  already carries `requires_human` for exactly this; it needs a one-line `if` on
  the publish job's environment.
- Keep the gate but scope it to phase 2 and 3, where a comment can actually block
  someone. In phase 1 the comment is advisory and the blast radius of a bad one
  is a wasted minute.

**Artifact retention is 90 days, the policy says 365.** GitHub caps artifact
retention below what the policy requires. `audit/run.json` needs shipping to a
real log store. Until that exists, the audit clause is not met.

**Restricted projects need a self-hosted runner.** MOHAP, KEZAD, and EDE route to
on-prem Ollama, which a GitHub-hosted runner cannot reach. Those repos need
`AI_REVIEW_RUNNER` pointing at a runner inside the network. If it is unset the
run abstains rather than falling back — correct behaviour, but it means those
repos get no reviews at all until the runner exists.

**`incremental_since_last_reviewed_sha` vs the full commit range.** The policy
says review incrementally; the merge-control requirement says apply controls to
every commit that could reach `main`. `_carry_forward` reconciles them: new
comments come from the incremental diff, but unresolved blocker/major findings
from earlier commits are re-counted into the verdict as long as the lines they
cite still exist. Confirm that reading is what the policy owner intended.

## Deliberately not built

Token-usage monitoring. That is a separate agent per the brief, and the gateway
quota already gives you the hard limit in the meantime.
