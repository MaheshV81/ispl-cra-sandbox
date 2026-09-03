"""Diff parsing and the evidence index used by post-agent validation.

The evidence index is the single source of truth for whether a finding is
grounded: a (path, line) pair either exists in the reviewed diff or it does not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def matches_any(path: str, patterns: list[str]) -> bool:
    """Glob match with `**` semantics, as used throughout the policy."""
    p = PurePosixPath(path)
    for pattern in patterns:
        if p.full_match(pattern) if hasattr(p, "full_match") else _fallback(path, pattern):
            return True
    return False


def _fallback(path: str, pattern: str) -> bool:
    """`**` -> any depth, `*` -> one segment, `?` -> one char."""
    rx = ["^"]
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            rx.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            rx.append(".*")
            i += 2
        elif c == "*":
            rx.append("[^/]*")
            i += 1
        elif c == "?":
            rx.append("[^/]")
            i += 1
        else:
            rx.append(re.escape(c))
            i += 1
    rx.append("$")
    return re.match("".join(rx), path) is not None


@dataclass
class ChangedFile:
    path: str
    status: str
    patch: str
    additions: int
    deletions: int
    commentable: set[int] = field(default_factory=set)

    @property
    def changed_lines(self) -> int:
        return self.additions + self.deletions


def commentable_lines(patch: str) -> set[int]:
    """New-file line numbers for added lines. Conservative on purpose: GitHub
    rejects comments outside the diff, and the policy requires every finding to
    cite a line that exists in it."""
    out: set[int] = set()
    n = 0
    for raw in patch.splitlines():
        hunk = HUNK_RE.match(raw)
        if hunk:
            n = int(hunk.group(1))
            continue
        if not raw:
            continue
        if raw[0] == "+":
            out.add(n)
            n += 1
        elif raw[0] == " ":
            n += 1
    return out


def annotate(patch: str) -> str:
    """Prefix each added/context line with its real new-file line number.

    Without this the model invents line numbers and post-agent validation drops
    almost everything it produces.
    """
    out: list[str] = []
    n = 0
    for raw in patch.splitlines():
        hunk = HUNK_RE.match(raw)
        if hunk:
            n = int(hunk.group(1))
            out.append(raw)
            continue
        if not raw:
            out.append(raw)
            continue
        if raw[0] in "+ ":
            out.append(f"{n:>6} | {raw}")
            n += 1
        else:
            out.append(f"       | {raw}")
    return "\n".join(out)


def build_index(files: list[ChangedFile]) -> dict[str, set[int]]:
    return {f.path: f.commentable for f in files}
