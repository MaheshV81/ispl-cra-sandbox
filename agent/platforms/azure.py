"""Azure DevOps adapter.

The awkward part, and the reason this file is longer than the GitHub one:
**Azure DevOps does not hand you a patch.** GitHub returns a `patch` field per
changed file. Azure returns a list of changed paths, and you must fetch each
file's content at the base and head commits and diff them yourself.

That matters beyond inconvenience. `commentable_lines` decides which lines a
finding may cite, and it parses unified diff hunks. So the diff this adapter
constructs has to be a real unified diff with correct `@@` headers, or evidence
validation silently rejects every finding and the agent abstains on every run.
Hence difflib.unified_diff rather than anything homemade.

Untested against a live Azure DevOps instance. The REST shapes follow the
published API, but treat the first run as a debugging session, not a smoke test.
"""

from __future__ import annotations

import base64
import difflib
import os
from typing import Any

import requests

from ..diff import ChangedFile, commentable_lines
from .base import InlineComment, Platform, PullRequest, PullRequestRef

API_VERSION = "7.1"

# Paths whose content is pointless to diff and expensive to fetch.
BINARY_HINTS = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip",
                ".dll", ".exe", ".woff", ".woff2", ".ttf", ".so", ".bin")


class AzureDevOpsPlatform(Platform):
    name = "azure"

    def __init__(self, base_url: str | None = None, pat: str | None = None):
        self.base_url = (base_url or os.environ["AZDO_BASE_URL"]).rstrip("/")
        pat = pat or os.environ["AZDO_PAT"]
        # Azure DevOps PAT auth is Basic with an empty username.
        token = base64.b64encode(f":{pat}".encode()).decode()
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
        })

    # -- helpers ----------------------------------------------------------

    def _repo_url(self, repo: str) -> str:
        org, project, name = repo.split("/", 2)
        return f"{self.base_url}/{org}/{project}/_apis/git/repositories/{name}"

    def _get(self, url: str, **params) -> dict:
        params.setdefault("api-version", API_VERSION)
        r = self.session.get(url, params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    # -- event ------------------------------------------------------------

    def parse_event(self, payload: dict) -> PullRequest | None:
        """Normalise an Azure DevOps Service Hook body.

        Relevant eventType values: git.pullrequest.created,
        git.pullrequest.updated. Anything else is not a reviewable event.
        """
        event_type = payload.get("eventType", "")
        if not event_type.startswith("git.pullrequest"):
            return None

        r = payload.get("resource") or {}
        repo_obj = r.get("repository") or {}
        project = (repo_obj.get("project") or {}).get("name", "")
        org = self._org_from_url(repo_obj.get("url", ""))
        repo = f"{org}/{project}/{repo_obj.get('name', '')}"

        pr_id = r.get("pullRequestId")
        if pr_id is None:
            return None

        # Azure reports draft as isDraft; status "abandoned" is not reviewable.
        if r.get("status") == "abandoned":
            return None

        return PullRequest(
            ref=PullRequestRef(self.name, repo, int(pr_id)),
            title=r.get("title") or "",
            body=r.get("description") or "",
            author=((r.get("createdBy") or {}).get("uniqueName")
                    or (r.get("createdBy") or {}).get("displayName") or ""),
            head_sha=(r.get("lastMergeSourceCommit") or {}).get("commitId", ""),
            base_sha=(r.get("lastMergeTargetCommit") or {}).get("commitId", ""),
            draft=bool(r.get("isDraft")),
            # Azure calls them labels but only populates them on request.
            labels={l.get("name") for l in (r.get("labels") or []) if l.get("name")},
            raw=payload,
        )

    @staticmethod
    def _org_from_url(url: str) -> str:
        # https://dev.azure.com/{org}/... or https://{org}.visualstudio.com/...
        if "dev.azure.com/" in url:
            return url.split("dev.azure.com/", 1)[1].split("/", 1)[0]
        if ".visualstudio.com" in url:
            return url.split("//", 1)[1].split(".visualstudio.com", 1)[0]
        return ""

    # -- diff -------------------------------------------------------------

    def fetch_changed_files(self, pr: PullRequest) -> list[ChangedFile]:
        return self._diff_between(pr, pr.base_sha, pr.head_sha)

    def fetch_changed_files_since(self, pr: PullRequest, base_sha: str) -> list[ChangedFile]:
        return self._diff_between(pr, base_sha, pr.head_sha)

    def _diff_between(self, pr: PullRequest, base: str, head: str) -> list[ChangedFile]:
        if not base or not head:
            return []
        repo_url = self._repo_url(pr.ref.repo)

        changes = self._get(
            f"{repo_url}/diffs/commits",
            baseVersion=base, baseVersionType="commit",
            targetVersion=head, targetVersionType="commit",
            **{"$top": 200},
        )

        out: list[ChangedFile] = []
        for entry in changes.get("changes", []):
            item = entry.get("item") or {}
            path = (item.get("path") or "").lstrip("/")
            change_type = (entry.get("changeType") or "").lower()

            if not path or item.get("gitObjectType") == "tree":
                continue
            if "delete" in change_type:
                continue
            if path.lower().endswith(BINARY_HINTS):
                continue

            new_text = self._file_at(repo_url, path, head)
            if new_text is None:
                continue  # binary or unreadable
            old_text = "" if "add" in change_type else (
                self._file_at(repo_url, path, base) or "")

            patch = self._unified(old_text, new_text, path)
            if not patch:
                continue

            cf = ChangedFile(
                path=path,
                status="added" if "add" in change_type else "modified",
                patch=patch,
                additions=sum(1 for l in patch.splitlines()
                              if l.startswith("+") and not l.startswith("+++")),
                deletions=sum(1 for l in patch.splitlines()
                              if l.startswith("-") and not l.startswith("---")),
            )
            cf.commentable = commentable_lines(cf.patch)
            out.append(cf)
        return out

    def _file_at(self, repo_url: str, path: str, commit: str) -> str | None:
        try:
            r = self.session.get(
                f"{repo_url}/items",
                params={"path": path, "versionDescriptor.version": commit,
                        "versionDescriptor.versionType": "commit",
                        "includeContent": "true", "api-version": API_VERSION},
                timeout=30,
            )
            if r.status_code == 404:
                return ""
            r.raise_for_status()
            body = r.json()
            content = body.get("content")
            return content if isinstance(content, str) else None
        except (requests.HTTPError, ValueError):
            return None

    @staticmethod
    def _unified(old: str, new: str, path: str) -> str:
        """Real unified diff with correct hunk headers.

        commentable_lines parses @@ markers to decide which lines a finding may
        cite. A malformed header here means every finding is rejected by
        evidence validation and the agent abstains without an obvious cause.
        """
        diff = difflib.unified_diff(
            old.splitlines(keepends=False),
            new.splitlines(keepends=False),
            fromfile=f"a/{path}", tofile=f"b/{path}",
            lineterm="", n=3,
        )
        lines = list(diff)
        # Drop the ---/+++ header; ChangedFile.patch holds hunks only, matching
        # what the GitHub adapter provides.
        return "\n".join(l for l in lines
                         if not l.startswith("--- ") and not l.startswith("+++ "))

    # -- comments ---------------------------------------------------------

    def agent_comments(self, pr: PullRequest, marker: str) -> list[dict]:
        repo_url = self._repo_url(pr.ref.repo)
        try:
            threads = self._get(f"{repo_url}/pullRequests/{pr.ref.number}/threads")
        except requests.HTTPError:
            return []

        out: list[dict] = []
        for thread in threads.get("value", []):
            for c in thread.get("comments", []):
                body = c.get("content") or ""
                if marker in body:
                    out.append({"body": body,
                                "created_at": c.get("publishedDate", "")})
        out.sort(key=lambda c: c["created_at"])
        return out

    def post_review(self, pr: PullRequest, summary: str,
                    comments: list[InlineComment]) -> None:
        """Summary as a standalone thread, each finding as its own file thread.

        Azure has no batch review object, so this is N+1 calls. Posted summary
        first: if an inline call fails partway, the reader still has the verdict
        rather than a random subset of findings.
        """
        repo_url = self._repo_url(pr.ref.repo)
        threads_url = f"{repo_url}/pullRequests/{pr.ref.number}/threads"

        self._post_thread(threads_url, {
            "comments": [{"parentCommentId": 0, "content": summary,
                          "commentType": "text"}],
            "status": "active",
        })

        for c in comments:
            self._post_thread(threads_url, {
                "comments": [{"parentCommentId": 0, "content": c.body,
                              "commentType": "text"}],
                "status": "active",
                "threadContext": {
                    "filePath": f"/{c.path}",
                    "rightFileStart": {"line": c.line, "offset": 1},
                    "rightFileEnd": {"line": c.line, "offset": 1},
                },
            })

    def _post_thread(self, url: str, payload: dict) -> None:
        r = self.session.post(url, json=payload,
                              params={"api-version": API_VERSION}, timeout=30)
        if r.status_code >= 300:
            print(f"::warning::azure thread post failed "
                  f"({r.status_code}): {r.text[:300]}")

    def post_status(self, pr: PullRequest, name: str, conclusion: str,
                    title: str, summary: str) -> None:
        """Advisory PR status.

        Deliberately never uses the `failed` state while phase 1 is active —
        the mapping below is driven by what guardrails.check_conclusion already
        decided, so blocking behaviour stays a policy decision, not a per-
        platform one.
        """
        state = {"neutral": "notApplicable",
                 "success": "succeeded",
                 "failure": "failed"}.get(conclusion, "notApplicable")
        repo_url = self._repo_url(pr.ref.repo)
        r = self.session.post(
            f"{repo_url}/pullRequests/{pr.ref.number}/statuses",
            json={
                "state": state,
                "description": title[:400],
                "context": {"name": name.replace(" ", "-"), "genre": "ispl-cra"},
            },
            params={"api-version": API_VERSION}, timeout=30,
        )
        if r.status_code >= 300:
            print(f"::warning::azure status post failed "
                  f"({r.status_code}): {r.text[:300]}")

    def fetch_file(self, pr: PullRequest, path: str, ref: str) -> str | None:
        return self._file_at(self._repo_url(pr.ref.repo), path, ref) or None
