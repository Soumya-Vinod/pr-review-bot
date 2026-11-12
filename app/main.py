"""FastAPI application: GET /health and POST /webhook.

The webhook handler only verifies the signature, filters the event, records a job
and returns 202. All slow work happens in the background worker (app.jobs).
"""

import json
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse

from app.config import Settings, get_settings
from app.webhooks import Ignored, filter_event, verify_signature

app = FastAPI(title="PR Review Bot")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/webhook")
async def webhook(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    x_hub_signature_256: Annotated[str | None, Header()] = None,
    x_github_event: Annotated[str | None, Header()] = None,
    x_github_delivery: Annotated[str | None, Header()] = None,
) -> JSONResponse:
    body = await request.body()
    secret = settings.github_webhook_secret.get_secret_value().encode("utf-8")
    if not verify_signature(secret, body, x_hub_signature_256):
        return JSONResponse({"detail": "invalid signature"}, status_code=401)

    if not x_github_event or not x_github_delivery:
        return JSONResponse(
            {"detail": "missing X-GitHub-Event or X-GitHub-Delivery"}, status_code=400
        )

    try:
        payload: Any = json.loads(body)
    except ValueError:
        return JSONResponse({"detail": "body is not valid JSON"}, status_code=400)
    if not isinstance(payload, dict):
        return JSONResponse({"detail": "body must be a JSON object"}, status_code=400)

    if x_github_event == "ping":
        return JSONResponse({"status": "pong"}, status_code=200)

    result = filter_event(x_github_event, x_github_delivery, payload)
    if isinstance(result, Ignored):
        return JSONResponse({"ignored": result.reason}, status_code=202)

    # Phase 5 records a job here; the worker does the review.
    return JSONResponse({"accepted": True, "delivery_id": result.delivery_id}, status_code=202)
