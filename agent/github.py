"""GitHub API access.

Only the calls the policy permits are implemented. There is deliberately no
approve, merge, push, or branch-mutation method anywhere in this module: the
guardrail that blocks write actions is stronger if the capability does not exist
in the first place.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Iterable

import requests

from .diff import ChangedFile, commentable_lines

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")

_session = requests.Session()
_session.headers.update({
    "Authorization": f"Bearer {os.environ.get('GITHUB_TOKEN', '')}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
})


def _paginate(url: str, params: dict | None = None) -> Iterable[dict]:
    params = dict(params or {})
    params.setdefault("per_page", 100)
    page = 1
    while True:
        params["page"] = page
        r = _session.get(url, params=params, timeout=30)
        r.raise_for_status()
        batch = r.json()
        if not batch:
            return
        yield from batch
        if len(batch) < params["per_page"]:
            return
        page += 1


# --- permitted tool: fetch_diff -------------------------------------------

def fetch_changed_files(repo: str, pr_number: int) -> list[ChangedFile]:
    files: list[ChangedFile] = []
    for item in _paginate(f"{API}/repos/{repo}/pulls/{pr_number}/files"):
        if item["status"] == "removed":
            continue
        patch = item.get("patch")
        if not patch:
            continue  # binary, or too large for GitHub to render
        cf = ChangedFile(
            path=item["filename"],
            status=item["status"],
            patch=patch,
            additions=item.get("additions", 0),
            deletions=item.get("deletions", 0),
        )
        cf.commentable = commentable_lines(patch)
        files.append(cf)
    return files


def compare_range(repo: str, base_sha: str, head_sha: str) -> list[ChangedFile]:
    """Incremental re-review: the diff between the last reviewed SHA and HEAD."""
    r = _session.get(f"{API}/repos/{repo}/compare/{base_sha}...{head_sha}", timeout=30)
    r.raise_for_status()
    files: list[ChangedFile] = []
    for item in r.json().get("files", []):
        if item["status"] == "removed" or not item.get("patch"):
            continue
        cf = ChangedFile(
            path=item["filename"], status=item["status"], patch=item["patch"],
            additions=item.get("additions", 0), deletions=item.get("deletions", 0),
        )
        cf.commentable = commentable_lines(item["patch"])
        files.append(cf)
    return files


# --- read helpers ----------------------------------------------------------

def get_labels(pr: dict) -> set[str]:
    return {lbl["name"] for lbl in pr.get("labels", [])}


def reviewed_shas(repo: str, pr_number: int, marker: str) -> set[str]:
    """SHAs already reviewed, read back from the footer of prior summary comments."""
    shas: set[str] = set()
    for c in _paginate(f"{API}/repos/{repo}/issues/{pr_number}/comments"):
        body = c.get("body") or ""
        if marker not in body:
            continue
        for line in body.splitlines():
            if line.strip().startswith("<!-- reviewed_sha:"):
                shas.add(line.split(":", 1)[1].strip().rstrip("->").strip())
    return shas


def run_history(repo: str, pr_number: int, marker: str) -> tuple[int, float | None]:
    """(runs already recorded on this PR, seconds since the most recent)."""
    stamps: list[datetime] = []
    for c in _paginate(f"{API}/repos/{repo}/issues/{pr_number}/comments"):
        if marker in (c.get("body") or ""):
            stamps.append(datetime.fromisoformat(c["created_at"].replace("Z", "+00:00")))
    if not stamps:
        return 0, None
    latest = max(stamps)
    return len(stamps), (datetime.now(timezone.utc) - latest).total_seconds()


def get_ci_status(repo: str, sha: str) -> str:
    r = _session.get(f"{API}/repos/{repo}/commits/{sha}/status", timeout=30)
    if r.status_code >= 300:
        return "unknown"
    return r.json().get("state", "unknown")


def detect_project(repo: str) -> str | None:
    """Project code for residency routing.

    Order: explicit env var, then a committed `.ai-review-project` file, then
    repo topics. Returns None if none of them answer, which routes the run to
    the restricted backend.
    """
    if os.environ.get("REVIEW_PROJECT"):
        return os.environ["REVIEW_PROJECT"].strip().upper()

    r = _session.get(f"{API}/repos/{repo}/contents/.ai-review-project", timeout=20)
    if r.status_code == 200:
        import base64
        raw = base64.b64decode(r.json().get("content", "")).decode(errors="ignore")
        if raw.strip():
            return raw.strip().splitlines()[0].strip().upper()

    r = _session.get(f"{API}/repos/{repo}/topics", timeout=20,
                     headers={"Accept": "application/vnd.github.mercy-preview+json"})
    if r.status_code == 200:
        for topic in r.json().get("names", []):
            if topic.lower().startswith("project-"):
                return topic.split("-", 1)[1].strip().upper()
    return None


# --- permitted tool: post_review_comment ----------------------------------

def post_review(repo: str, pr_number: int, commit_sha: str, body: str,
                comments: list[dict]) -> None:
    """Post the summary and inline comments as one review.

    event is always COMMENT. The agent is forbidden from approving, and
    REQUEST_CHANGES is a review state that can satisfy branch protection, which
    would breach the invariant that the agent never counts toward a required
    human approval. The verdict is carried in the comment text and the check run.
    """
    url = f"{API}/repos/{repo}/pulls/{pr_number}/reviews"
    payload = {"commit_id": commit_sha, "body": body, "event": "COMMENT",
               "comments": comments}
    r = _session.post(url, json=payload, timeout=60)
    if r.status_code >= 300:
        print(f"::warning::inline review rejected ({r.status_code}); posting summary only")
        r = _session.post(url, json={"commit_id": commit_sha, "body": body,
                                     "event": "COMMENT"}, timeout=60)
        r.raise_for_status()


def post_check_run(repo: str, head_sha: str, name: str, conclusion: str,
                   title: str, summary: str) -> None:
    r = _session.post(
        f"{API}/repos/{repo}/check-runs",
        json={"name": name, "head_sha": head_sha, "status": "completed",
              "conclusion": conclusion,
              "output": {"title": title, "summary": summary[:65000]}},
        timeout=30,
    )
    if r.status_code >= 300:
        print(f"::warning::check run creation failed ({r.status_code}): {r.text[:300]}")
