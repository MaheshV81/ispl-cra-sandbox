# Stage 2 — run the agent on a sandbox repo

Picking up from LangSmith stage 1, which is done. This gets the agent running on
a throwaway GitHub repo before it goes anywhere near `intertec/*`.

Everything here is Windows PowerShell, matching what you have been using.

---

## Why a sandbox policy exists

Four things in ISPL-CRA-001 will stop the agent dead on a personal repo. You
would hit them one at a time, each with a different confusing message. So there
is a second policy file, `review_policy.sandbox.yaml`, with those four changed
and nothing else:

| What | Production | Sandbox | If you did not change it |
|---|---|---|---|
| `allowed_repos` | `intertec/*` | your repo | Every run stops: "repo is outside scope.allowed_repos" |
| `unknown_project_behaviour` | `restricted` | `default` | Your repo has no project code, so it routes to on-prem Ollama, which you do not have, and abstains |
| `default_model` | Sonnet via Higress | Haiku direct | Calls a gateway that does not exist |
| `human_approval_required` | `[post_review_comment]` | `[]` | Job waits forever for an environment approval you have not configured |

Guardrails, evidence rules, verdict arithmetic, and phase-1 advisory behaviour
are byte-identical between the two. You are testing the real logic.

---

## Step 1 — Create the repo

github.com → **New repository**.

- Name: `ispl-cra-sandbox`
- **Public** (see the note below)
- Tick **Add a README file**
- Create

**On public vs private.** Make it public. There is no real code in it, and
GitHub's environment protection rules — the required-reviewer feature the
approval gate depends on — are not available on private repos for personal
accounts. If you make it private you can still test everything except the gate.
Your call, but public is simpler and this repo holds nothing.

## Step 2 — Get the files onto your machine

Download `ispl-cra-sandbox.zip` from the file card below and unzip it.

```powershell
cd $env:USERPROFILE\ispl-cra
Expand-Archive $env:USERPROFILE\Downloads\ispl-cra-sandbox.zip -DestinationPath . -Force
dir
```

You should see `agent`, `policy`, `sandbox`, `.github`, and `requirements.txt`.

## Step 3 — Edit one line

Open `policy\review_policy.sandbox.yaml`. Find:

```yaml
  allowed_repos:
    - "YOUR-GITHUB-USERNAME/ispl-cra-sandbox"
```

Replace with your actual GitHub username, keeping the repo name. Case matters.

```powershell
notepad policy\review_policy.sandbox.yaml
```

This is the single most common reason a first run does nothing.

## Step 4 — Push

If you have git installed:

```powershell
git init
git remote add origin https://github.com/YOUR-USERNAME/ispl-cra-sandbox.git
git branch -M main
git add .
git commit -m "Add ISPL-CRA sandbox review agent"
git push -u origin main --force
```

`--force` because GitHub created a README commit you are overwriting. Fine on a
sandbox; never do this on a real repo.

If git is not installed, use github.com's web upload — drag the folders into the
repo page. Slower, but it works.

## Step 5 — Add secrets

Repo → Settings → Secrets and variables → Actions → **New repository secret**.

| Name | Value |
|---|---|
| `ANTHROPIC_API_KEY` | from console.anthropic.com → API Keys |
| `LANGSMITH_API_KEY` | your replacement LangSmith key |

You need a funded Anthropic account for the first one. A sandbox PR on Haiku
costs a fraction of a cent, but the account needs credit on it.

`GITHUB_TOKEN` is injected automatically. Do not create one.

## Step 6 — Create the LangSmith project

Still outstanding from stage 1, and the workflow writes to it.

LangSmith → **Tracing** → **+ New Project** → name it `ispl-cra`.

Then Projects → `ispl-cra` → **Retention** → **Extended**.

Do this before the first run. Base is 14 days; the setting only applies to
traces that arrive after you change it.

## Step 7 — Open a test PR

```powershell
git checkout -b test/first-review
git add sandbox/sample_defects.py
git commit -m "Add sample file with known defects"
git push -u origin test/first-review
```

Then open the PR on github.com.

`sample_defects.py` has five planted defects at known severities, listed in its
docstring. It is a fixture: you know the right answer, so you can judge whether
the agent is right.

## Step 8 — Read the run

Actions tab → the running workflow → the `Analyze` step.

**Expected:**

```
project=SANDBOX restricted=False model=anthropic:claude-haiku-4-5-20251001
verdict=request_changes findings=4 inline=4 rejected=1 escalate=True
```

Numbers will vary. What matters:

- `restricted=False` — routing is right
- `findings` between 3 and 6 — it found the planted defects
- `rejected` low — most findings survived evidence validation
- `escalate=True` — expected, since there is a security blocker in the fixture

Then look at the PR. You should see a summary comment with a verdict table, and
inline comments with suggestion blocks on the blocker and major findings.

## Step 9 — Compare against the fixture

Open `sandbox/sample_defects.py` and read the docstring. Five defects are listed.

- **Found a defect not on the list?** False positive. Worth reading its rationale
  — the trace shows what it was looking at.
- **Missed a blocker?** The SQL injection in `get_user` is the one it must
  catch. If it missed that, something is wrong with the prompt or the diff
  annotation.
- **`rejected` is high?** The model is citing lines outside the diff. Post the
  number and I will look at it.

This is the only time you will have ground truth. Use it.

## Step 10 — Check the trace

LangSmith → Tracing → `ispl-cra`. One trace per run.

Inputs and outputs will be **empty**. That is `hide_inputs`/`hide_outputs`
honouring `redact_code_in_logs`, and it is correct. Everything useful is on the
metadata tab: run ID, policy version, repo, project, model, residency route,
token counts. Feedback carries verdict, findings count, rejected count, and
whether it escalated.

The `run_id` matches `GITHUB_RUN_ID` in the Actions URL and the first field of
`audit/run.json` in the workflow artifacts. One ID, three systems.

---

## When something goes wrong

| Symptom | Cause |
|---|---|
| `repo X is outside scope.allowed_repos` | Step 3 not done, or username typo |
| `model call failed ... 404` | Model string not available on your account. Change `default_model` in the sandbox policy |
| `model call failed ... 401` | `ANTHROPIC_API_KEY` secret missing or wrong |
| `credit balance too low` | Fund the Anthropic account |
| Workflow does not trigger | Workflow file must be on `main` before it runs on PRs |
| `Resource not accessible by integration` | Settings → Actions → General → Workflow permissions → Read and write |
| No trace in LangSmith | `LANGSMITH_API_KEY` secret missing. Check the log for a `tracing off` notice |
| `tracing disabled — residency` | Sandbox policy has empty `restricted_projects`, so this should not appear. If it does, `REVIEW_POLICY_PATH` is pointing at the wrong file |
| Review posts nothing, no error | Check the `Analyze` log for a `::notice::` line — a guardrail stopped it, and it says which |

---

## After it works

Three things to try, in order:

1. **Add `human_approval_required: ["post_review_comment"]`** back to the
   sandbox policy, create the `ai-review-publish` environment with yourself as
   required reviewer, and switch to the two-job production workflow. Now you have
   seen both gate variants and the decision memo becomes concrete.
2. **Push a second commit** to the same PR. Watch incremental re-review — it only
   looks at the new diff, but carries forward unresolved findings into the
   verdict.
3. **Open a PR touching `sandbox/auth/`**. Sensitive-path escalation should fire
   even with no findings at all.

Then the remaining gap for production is the one thing a sandbox cannot prove:
the on-prem Ollama route for MOHAP, KEZAD, and EDE. That needs a self-hosted
runner inside your network, and it is the piece I would sequence next.
