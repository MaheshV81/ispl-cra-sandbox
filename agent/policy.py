"""Policy loading. The YAML is authoritative; this module only reads it.

Every accessor fails closed: a missing key raises rather than defaulting to a
permissive value.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

import yaml

POLICY_PATH = os.environ.get("REVIEW_POLICY_PATH", "policy/review_policy.yaml")


class PolicyError(RuntimeError):
    """Raised when the policy is missing, malformed, or does not cover a case."""


@lru_cache(maxsize=1)
def load() -> dict[str, Any]:
    try:
        with open(POLICY_PATH) as fh:
            policy = yaml.safe_load(fh)
    except FileNotFoundError as exc:
        raise PolicyError(f"policy not found at {POLICY_PATH}") from exc

    for section in ("trigger", "scope", "data", "authority", "review", "output",
                    "branch_protection", "audit"):
        if section not in policy:
            raise PolicyError(f"policy is missing required section: {section}")
    return policy


def get(path: str) -> Any:
    """Dotted lookup. Raises rather than returning None."""
    node: Any = load()
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            raise PolicyError(f"policy key not found: {path}")
        node = node[part]
    return node


def phase() -> dict[str, Any]:
    """The active branch-protection phase definition."""
    current = get("branch_protection.current_phase")
    phases = get("branch_protection.phases")
    if current not in phases:
        raise PolicyError(f"current_phase {current} is not defined in phases")
    return {"number": current, **phases[current]}


def severity_rank(severity: str) -> int:
    order = get("review.severities")  # ["blocker", "major", "minor", "nit"]
    try:
        return order.index(severity)
    except ValueError as exc:
        raise PolicyError(f"unknown severity: {severity}") from exc
