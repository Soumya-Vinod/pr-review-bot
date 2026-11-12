"""FastAPI application: GET /health and POST /webhook.

The webhook handler only verifies the signature, filters the event, records a job
and returns 202. All slow work happens in the background worker (app.jobs), which is
started and stopped by the app lifespan.
"""

import json
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Annotated, Any

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from app.config import Settings, get_settings
from app.db import create_tables, make_engine
from app.github_client import GitHubClient
from app.jobs import ReviewPipeline, Worker, WorkerConfig, enqueue_job, recover_stuck_jobs
from app.webhooks import Ignored, filter_event, verify_signature

logger = logging.getLogger(__name__)


def create_app(
    settings_provider: Callable[[], Settings] = get_settings,
    *,
    run_worker: bool = True,
    worker_config: WorkerConfig | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings = settings_provider()
        app.state.settings = settings
        app.state.engine = None
        app.state.worker = None
        async with AsyncExitStack() as stack:
            if settings.database_url is None:
                logger.warning("DATABASE_URL is not set: pull_request events will get 503")
            else:
                engine = make_engine(settings.database_url.get_secret_value())
                stack.push_async_callback(engine.dispose)
                await create_tables(engine)
                app.state.engine = engine
                if run_worker:
                    recovered = await recover_stuck_jobs(engine, worker_config)
                    if recovered:
                        logger.info("recovered %d stuck job(s)", recovered)
                    github = GitHubClient(settings.github_app_id, settings.private_key_pem())
                    stack.push_async_callback(github.aclose)
                    pipeline = ReviewPipeline(engine, github, settings.bot_comment_marker)
                    worker = Worker(engine, pipeline, worker_config)
                    worker.start()
                    stack.push_async_callback(worker.stop)  # runs first on shutdown
                    app.state.worker = worker
            yield

    app = FastAPI(title="PR Review Bot", lifespan=lifespan)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/webhook")
    async def webhook(
        request: Request,
        x_hub_signature_256: Annotated[str | None, Header()] = None,
        x_github_event: Annotated[str | None, Header()] = None,
        x_github_delivery: Annotated[str | None, Header()] = None,
    ) -> JSONResponse:
        settings: Settings = request.app.state.settings
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

        engine = request.app.state.engine
        if engine is None:
            return JSONResponse({"detail": "database not configured"}, status_code=503)
        if not await enqueue_job(engine, result):
            return JSONResponse({"duplicate": True}, status_code=202)
        worker: Worker | None = request.app.state.worker
        if worker is not None:
            worker.notify()
        return JSONResponse({"queued": True, "delivery_id": result.delivery_id}, status_code=202)

    return app


app = create_app()
