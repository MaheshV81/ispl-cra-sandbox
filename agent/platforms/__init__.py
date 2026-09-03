"""Platform adapter registry.

Adding a forge means adding an adapter here. It must not mean touching
guardrails, policy, or verdict logic — if it does, the abstraction has leaked
and the same pull request could be judged differently depending on where it
lives.
"""

from __future__ import annotations

from .base import InlineComment, Platform, PullRequest, PullRequestRef

__all__ = ["InlineComment", "Platform", "PullRequest", "PullRequestRef", "get"]


def get(name: str) -> Platform:
    if name == "github":
        from .github import GitHubPlatform
        return GitHubPlatform()
    if name == "azure":
        from .azure import AzureDevOpsPlatform
        return AzureDevOpsPlatform()
    raise ValueError(f"unknown platform: {name}")


def detect(payload: dict, headers: dict[str, str] | None = None) -> str | None:
    """Identify the sender from the webhook body or headers."""
    headers = {k.lower(): v for k, v in (headers or {}).items()}
    if "x-github-event" in headers:
        return "github"
    if payload.get("eventType", "").startswith("git.pullrequest"):
        return "azure"
    if "pull_request" in payload and "repository" in payload:
        return "github"
    return None
