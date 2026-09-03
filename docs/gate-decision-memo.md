# Decision memo — approval gate for ISPL-CRA-001

**To:** Delivery AI Governance (policy owner)
**Re:** `authority.human_approval_required: ["post_review_comment"]`
**Decision needed:** keep the clause as written (Variant A) or amend it to apply
only on escalation (Variant B).
**Status:** both variants are built and testable. Neither is deployed.

---

## The clause

```yaml
authority:
  human_approval_required:
    - "post_review_comment"
```

`post_review_comment` is the agent's only write action. Requiring approval for it
means requiring approval for every review the agent produces, on every pull
request, in every in-scope repo.

## What each variant does

| | Variant A — universal gate | Variant B — escalation-only gate |
|---|---|---|
| Routine review (no blocker, no security finding, no sensitive path, clean validation) | waits for a named approver | posts unattended |
| Escalated review (any `escalate_to_human_when` condition) | waits for a named approver | waits for a named approver |
| Approvals per 100 PRs, est. | 100 | 15–30 |
| Policy change needed | none | yes, see below |
| Agent code change needed | none | none |
| File | `.github/workflows/ai-review.yml` | `.github/workflows/ai-review-escalation-only.yml` |

The estimate of 15–30 is a guess, not a measurement. It assumes most PRs are
clean and the escalation triggers are dominated by the sensitive-path condition.
Phase 1 exists to replace that guess with a number, and the decision could
reasonably be deferred until it has.

## The case for Variant A

Every published artefact carries a named human. Nothing the agent writes reaches
a developer without someone accountable having seen it. For a first deployment
against client codebases under a governance policy, that is a defensible posture
and it is what the clause as drafted asks for.

It also fails safe on an unknown. Nobody has yet seen this agent's output on
these repos. A universal gate means the first bad review is caught by a person
rather than by the developer it lands on.

## The case for Variant B

**The failure mode of Variant A is not delay, it is rubber-stamping.** A tech
lead asked to approve every review on every PR will, within about two weeks,
approve without reading. The gate then still produces an audit record asserting
that a named human authorised the post. That record is now false, and it is worse
than having no gate at all: an absent control is a known gap, while a
rubber-stamped control is a gap that the audit trail actively conceals.

`audit.log_fields` includes `human_decision`. Under Variant A that field will
read `approved_post_by:<name>` on every run regardless of whether anyone looked.
The field stops carrying information on the day the gate becomes routine.

**Phase 1 is advisory, which caps the blast radius.** `check_blocking: false`
means a bad comment costs a developer a minute of reading. It cannot block a
merge, fail a build, or gate a release. The cost of an unreviewed bad comment in
phase 1 is close to zero; the cost of a bottleneck on every PR is not.

**Variant B keeps the gate where it earns its cost.** The
`escalate_to_human_when` conditions are already the policy's own definition of
"a human should see this": blocker severity, security category, sensitive path,
validation failure, sub-floor confidence. Variant B gates exactly that set and
nothing else. It is not a weakening of the escalation clause — it is the
escalation clause doing the work it was written for.

## Recommendation

Variant B, with two conditions:

1. **Revisit at phase 2.** When `check_blocking` becomes true, a comment can
   block a merge and the blast radius changes. Re-open this decision then.
2. **Distinguish the two paths in the audit record.** Variant B writes
   `human_decision: approved_post_by:automated-routine` on the ungated path and
   `approved_post_by:<login>` on the gated one. The audit trail must never imply
   a human reviewed something automatic. This is already implemented.

If Governance prefers Variant A, that is a legitimate call and the workflow is
ready. The one outcome to avoid is adopting Variant A and then quietly widening
approver membership or enabling auto-approval to relieve the load, which
produces Variant B's coverage with Variant A's paperwork.

## Required policy amendment for Variant B

```diff
 authority:
   human_approval_required:
-    - "post_review_comment"
+    - "post_review_comment_when_escalated"
```

Optionally make the intent explicit rather than leaving it implied by the
clause name:

```yaml
authority:
  human_approval_required:
    - "post_review_comment_when_escalated"
  approval_gate:
    applies_when: "any condition in escalate_to_human_when is met"
    routine_posts: "unattended, recorded as human_decision=automated-routine"
    review_at_phase: 2
```

Bump `policy_version` to `1.2.0`. The version is written into every summary
comment footer and every audit record, so the change is self-documenting in the
trail.

`main.py` already computes:

```python
"requires_human": bool(escalations)
    or "post_review_comment" in policy.get("authority.human_approval_required")
```

Removing the literal string from the policy flips the behaviour. No Python
changes, which means the amendment is reviewable by reading the YAML diff alone.

## Deployment note

The two workflows must not both be active. Both trigger on the same events and
share a concurrency group, so installing both produces duplicate analyses and
duplicate comments. Delete the unused file rather than disabling it.
