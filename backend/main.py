"""NetMind AI backend entry point.

Run with: uvicorn backend.main:app --host 0.0.0.0 --port 8000
"""

import logging

from backend.api.app import app
from backend.config import get_settings


def _configure_logging() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


_configure_logging()


def main() -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "backend.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.environment == "development",
    )


if __name__ == "__main__":
    main()
