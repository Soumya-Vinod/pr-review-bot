"""FastAPI application: GET /health and POST /webhook.

The webhook handler only verifies the signature, filters the event, records a job
and returns 202. All slow work happens in the background worker (app.jobs).
"""

from fastapi import FastAPI

app = FastAPI(title="PR Review Bot")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
