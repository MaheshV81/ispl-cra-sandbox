"""Platform abstraction.

The guardrails, evidence rules, verdict arithmetic, residency routing, and budget
ceilings are all platform-neutral already. Only two things ever were
GitHub-specific: fetching the diff and posting the review. This module is the
seam between them.

A platform adapter is responsible for exactly four things:

  1. normalising a webhook payload into a PullRequest
  2. producing a unified diff per changed file
  3. posting a summary and inline comments
  4. posting an advisory status

Everything else — what counts as in scope, what severity blocks, what the verdict
is, what may be traced — stays in policy and guardrails, identically across
platforms. That is the point: one policy, one audit stream, many forges.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PullRequestRef:
    """Platform-qualified identity of a pull request.

    `repo` is the platform's native form:
      github  ->  "owner/repo"
      azure   ->  "organisation/project/repo"

    Scope matching is done against f"{platform}:{repo}", so a policy can permit
    a GitHub repo without implicitly permitting an identically named Azure one.
    """
    platform: str
    repo: str
    number: int

    @property
    def qualified(self) -> str:
        return f"{self.platform}:{self.repo}"

    def __str__(self) -> str:
        return f"{self.qualified}#{self.number}"


@dataclass
class PullRequest:
    ref: PullRequestRef
    title: str
    body: str
    author: str
    head_sha: str
    base_sha: str
    draft: bool = False
    labels: set[str] = field(default_factory=set)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class InlineComment:
    path: str
    line: int
    body: str


class Platform(ABC):
    """One implementation per forge. Keep them thin.

    Anything resembling a policy decision that appears in an adapter is a bug:
    it would mean the same pull request could be judged differently on GitHub
    than on Azure DevOps, which defeats having a single policy at all.
    """

    name: str = "unknown"

    @abstractmethod
    def parse_event(self, payload: dict) -> PullRequest | None:
        """Normalise a webhook body. Return None if it is not a reviewable event."""

    @abstractmethod
    def fetch_changed_files(self, pr: PullRequest) -> list:
        """Changed files with a unified diff patch, as `diff.ChangedFile`."""

    @abstractmethod
    def fetch_changed_files_since(self, pr: PullRequest, base_sha: str) -> list:
        """Incremental diff between a previously reviewed commit and HEAD."""

    @abstractmethod
    def agent_comments(self, pr: PullRequest, marker: str) -> list[dict]:
        """Prior comments this agent posted, newest last.

        Each item needs at least `body` and `created_at`. These carry the
        reviewed-SHA list, the unresolved-finding state, and the running token
        total, because the runner is ephemeral and there is no database.
        """

    @abstractmethod
    def post_review(self, pr: PullRequest, summary: str,
                    comments: list[InlineComment]) -> None:
        """Post the summary and inline comments.

        Must never approve or request changes in a way the platform counts
        toward a required human approval — see branch_protection.invariants.
        """

    @abstractmethod
    def post_status(self, pr: PullRequest, name: str, conclusion: str,
                    title: str, summary: str) -> None:
        """Advisory status. `conclusion` is one of neutral, success, failure."""

    @abstractmethod
    def fetch_file(self, pr: PullRequest, path: str, ref: str) -> str | None:
        """File content at a commit, or None if absent or binary.

        Implements the read_file_at_ref and lookup_coding_standard tools that
        authority.permitted_tools already allows. Read-only by construction.
        """
