"""GitHub adapter. A thin re-expression of the original agent/github.py.

Nothing here decides anything. Compare with azure.py: GitHub hands back a
`patch` per file, so this adapter is roughly a third the size. That asymmetry is
entirely about what the two APIs provide, not about how the two platforms are
governed.
"""

from __future__ import annotations

import os
from typing import Iterable

import requests

from ..diff import ChangedFile, commentable_lines
from .base import InlineComment, Platform, PullRequest, PullRequestRef


class GitHubPlatform(Platform):
    name = "github"

    def __init__(self, api: str | None = None, token: str | None = None):
        self.api = (api or os.environ.get("GITHUB_API_URL",
                                          "https://api.github.com")).rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token or os.environ['GITHUB_TOKEN']}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def _paginate(self, url: str, params: dict | None = None) -> Iterable[dict]:
        params = dict(params or {})
        params.setdefault("per_page", 100)
        page = 1
        while True:
            params["page"] = page
            r = self.session.get(url, params=params, timeout=30)
            r.raise_for_status()
            batch = r.json()
            if not batch:
                return
            yield from batch
            if len(batch) < params["per_page"]:
                return
            page += 1

    def parse_event(self, payload: dict) -> PullRequest | None:
        pr = payload.get("pull_request")
        if not pr:
            return None
        repo = (payload.get("repository") or {}).get("full_name", "")
        if not repo:
            return None
        return PullRequest(
            ref=PullRequestRef(self.name, repo, pr["number"]),
            title=pr.get("title") or "",
            body=pr.get("body") or "",
            author=(pr.get("user") or {}).get("login", ""),
            head_sha=pr["head"]["sha"],
            base_sha=pr["base"]["sha"],
            draft=bool(pr.get("draft")),
            labels={l["name"] for l in pr.get("labels", [])},
            raw=payload,
        )

    def _to_changed(self, item: dict) -> ChangedFile | None:
        if item["status"] == "removed" or not item.get("patch"):
            return None
        cf = ChangedFile(
            path=item["filename"], status=item["status"], patch=item["patch"],
            additions=item.get("additions", 0), deletions=item.get("deletions", 0),
        )
        cf.commentable = commentable_lines(cf.patch)
        return cf

    def fetch_changed_files(self, pr: PullRequest) -> list[ChangedFile]:
        url = f"{self.api}/repos/{pr.ref.repo}/pulls/{pr.ref.number}/files"
        return [c for c in (self._to_changed(i) for i in self._paginate(url)) if c]

    def fetch_changed_files_since(self, pr: PullRequest, base_sha: str) -> list[ChangedFile]:
        r = self.session.get(
            f"{self.api}/repos/{pr.ref.repo}/compare/{base_sha}...{pr.head_sha}",
            timeout=30)
        r.raise_for_status()
        return [c for c in (self._to_changed(i) for i in r.json().get("files", [])) if c]

    def agent_comments(self, pr: PullRequest, marker: str) -> list[dict]:
        url = f"{self.api}/repos/{pr.ref.repo}/issues/{pr.ref.number}/comments"
        try:
            return [{"body": c.get("body") or "", "created_at": c["created_at"]}
                    for c in self._paginate(url) if marker in (c.get("body") or "")]
        except requests.HTTPError:
            return []

    def post_review(self, pr: PullRequest, summary: str,
                    comments: list[InlineComment]) -> None:
        # event is always COMMENT. REQUEST_CHANGES is a review state that can
        # satisfy branch protection, which would breach the invariant that the
        # agent never counts toward a required human approval.
        url = f"{self.api}/repos/{pr.ref.repo}/pulls/{pr.ref.number}/reviews"
        payload = {
            "commit_id": pr.head_sha, "body": summary, "event": "COMMENT",
            "comments": [{"path": c.path, "line": c.line, "side": "RIGHT",
                          "body": c.body} for c in comments],
        }
        r = self.session.post(url, json=payload, timeout=60)
        if r.status_code >= 300:
            print(f"::warning::inline review rejected ({r.status_code}); summary only")
            r = self.session.post(url, json={"commit_id": pr.head_sha,
                                             "body": summary,
                                             "event": "COMMENT"}, timeout=60)
            r.raise_for_status()

    def post_status(self, pr: PullRequest, name: str, conclusion: str,
                    title: str, summary: str) -> None:
        r = self.session.post(
            f"{self.api}/repos/{pr.ref.repo}/check-runs",
            json={"name": name, "head_sha": pr.head_sha, "status": "completed",
                  "conclusion": conclusion,
                  "output": {"title": title, "summary": summary[:65000]}},
            timeout=30)
        if r.status_code >= 300:
            print(f"::warning::check run failed ({r.status_code}): {r.text[:300]}")
