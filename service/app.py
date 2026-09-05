"""Central webhook service.

One deployment, both forges, one policy, one audit stream. This is the piece
that makes the audit trail verifiable: when every review runs from the same
process reading the same policy file, `policy_version: 1.1.0` in an audit record
means something. With the agent copied into thirty repos it does not.

Deployment note that is not optional: this service holds credentials for GitHub,
Azure DevOps, and the model provider simultaneously. It is a higher-value target
than anything the per-repo design created. Restricted projects also require it
to run inside your network, so on-prem hosting is a requirement rather than a
preference — and that is the same requirement the on-prem Ollama route already
imposes, so it is one piece of infrastructure, not two.

Run:
    pip install fastapi uvicorn
    uvicorn service.app:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Any

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request

from agent import platforms

app = FastAPI(title="ISPL-CRA review service")


# --------------------------------------------------------------------------
# Webhook authentication
# --------------------------------------------------------------------------

def _verify_github(body: bytes, signature: str | None) -> None:
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(500, "GITHUB_WEBHOOK_SECRET is not configured")
    if not signature:
        raise HTTPException(401, "missing signature")
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    # Constant-time. A timing side channel on a signature check is the kind of
    # finding this agent would flag in someone else's code.
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(401, "bad signature")


def _verify_azure(auth: str | None) -> None:
    """Azure DevOps Service Hooks do not sign payloads.

    They support HTTP Basic auth on the subscription instead, which is weaker:
    a shared secret in a header rather than a signature over the body. Configure
    it, keep this endpoint on TLS, and treat the payload as untrusted regardless.
    """
    expected = os.environ.get("AZDO_WEBHOOK_BASIC")
    if not expected:
        raise HTTPException(500, "AZDO_WEBHOOK_BASIC is not configured")
    if not auth or not hmac.compare_digest(auth, f"Basic {expected}"):
        raise HTTPException(401, "bad credentials")


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    background: BackgroundTasks,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
) -> dict[str, Any]:
    body = await request.body()
    _verify_github(body, x_hub_signature_256)

    if x_github_event != "pull_request":
        return {"accepted": False, "reason": f"ignoring event {x_github_event}"}

    payload = await request.json()
    return _dispatch("github", payload, background)


@app.post("/webhook/azure")
async def azure_webhook(
    request: Request,
    background: BackgroundTasks,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _verify_azure(authorization)
    payload = await request.json()
    return _dispatch("azure", payload, background)


def _dispatch(platform_name: str, payload: dict, background: BackgroundTasks) -> dict[str, Any]:
    """Normalise, then hand off.

    Returns immediately. Both platforms time out webhook deliveries and will
    retry on a slow response, which would produce duplicate reviews — so the
    review runs in the background and the ack is instant.
    """
    platform = platforms.get(platform_name)
    pr = platform.parse_event(payload)
    if pr is None:
        return {"accepted": False, "reason": "not a reviewable pull request event"}

    background.add_task(_run_review, platform_name, pr.ref.repo, pr.ref.number)
    return {"accepted": True, "pull_request": str(pr.ref)}


def _run_review(platform_name: str, repo: str, number: int) -> None:
    """Run the agent.

    Deliberately re-fetches the pull request rather than trusting the webhook
    body. Webhook payloads are attacker-influenced input on a public endpoint,
    and the draft flag, labels, and head SHA all feed scope admission. Reading
    them back from the API costs one call and removes a whole class of problem.
    """
    from agent import runner  # imported here so a bad review cannot break startup

    try:
        runner.review(platform_name, repo, number)
    except Exception as exc:  # noqa: BLE001
        # Never let one bad review take the service down. The audit record and
        # the abstain path already carry the detail.
        print(f"[error] review failed for {platform_name}:{repo}#{number}: {exc}")
