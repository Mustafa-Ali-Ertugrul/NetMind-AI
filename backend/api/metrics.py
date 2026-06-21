"""Prometheus metrics exports for the API layer."""

from fastapi import Request, Response
from prometheus_client import REGISTRY, Counter, Gauge, Histogram, generate_latest
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

request_count = Counter(
    "netmind_http_requests_total",
    "Total HTTP requests",
    labelnames=["method", "path", "status"],
)

request_duration = Histogram(
    "netmind_http_request_duration_seconds",
    "HTTP request duration in seconds",
    labelnames=["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)

in_flight = Gauge(
    "netmind_http_in_flight_requests",
    "Currently active HTTP requests",
)


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware that collects Prometheus metrics on each request."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method

        in_flight.inc()
        with request_duration.labels(method=method, path=path).time():
            response: Response = await call_next(request)
        in_flight.dec()

        request_count.labels(method=method, path=path, status=response.status_code).inc()
        return response


async def metrics_endpoint(request: Request) -> StarletteResponse:
    """Serve Prometheus metrics at /metrics."""
    content = generate_latest(REGISTRY)
    return StarletteResponse(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "no-cache"},
    )
