"""FastAPI application factory and entry point."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from backend.api.metrics import MetricsMiddleware, metrics_endpoint
from backend.api.rate_limit import limiter
from backend.api.routes import health, jobs, live, pcaps, storage
from backend.config import get_settings
from backend.storage.database import SyncSessionLocal, init_db
from backend.live_engine.service import LiveEngineService

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan: init DB on startup, log on shutdown."""
    settings = get_settings()
    logger.info(
        "Starting %s v%s (env=%s)",
        settings.app_name,
        settings.app_version,
        settings.environment,
    )
    try:
        await init_db()
        logger.info("Database schema initialized")
    except Exception as exc:
        logger.error("Database initialization failed: %s", exc)
        raise

    # ── Live engine service ─────────────────────────────────
    live_service = LiveEngineService()
    try:
        live_service.bind_writers(SyncSessionLocal)
        await live_service.start()
        logger.info("Live engine service started")
    except Exception as exc:
        logger.warning("Live engine service failed to start: %s", exc)
        live_service = None
    app.state.live_service = live_service

    yield

    # ── Shutdown ────────────────────────────────────────────
    if live_service is not None:
        await live_service.stop()
        logger.info("Live engine service stopped")
    logger.info("Shutting down %s", settings.app_name)


def create_app() -> FastAPI:
    """Build and return a configured FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="AI-powered network traffic analysis platform",
        lifespan=lifespan,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url="/redoc" if settings.enable_docs else None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )

    # ── Rate limiter ────────────────────────────────────────
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]
    app.add_middleware(SlowAPIMiddleware)  # type: ignore[arg-type]

    # ── CORS ────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Prometheus metrics ──────────────────────────────────
    app.add_middleware(MetricsMiddleware)

    # ── Routers ─────────────────────────────────────────────
    app.include_router(health.router)
    app.include_router(pcaps.router, prefix=settings.api_prefix)
    app.include_router(jobs.router, prefix=settings.api_prefix)
    app.include_router(storage.router, prefix=settings.api_prefix)
    app.include_router(live.router, prefix=settings.api_prefix)

    # Prometheus /metrics endpoint (registered after routers)
    @app.get("/metrics", include_in_schema=False)
    async def metrics(request: Request) -> Any:
        return await metrics_endpoint(request)

    return app


app = create_app()
