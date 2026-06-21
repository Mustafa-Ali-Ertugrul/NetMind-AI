"""HTTP summary builder: method/status counts, top URIs, user agents."""

from collections import Counter
from urllib.parse import urlparse

from backend.contracts.parser_output import ParsedHTTP

from .constants import TOP_HTTP_URIS


class HTTPSummaryBuilder:
    """Accumulate HTTP requests and produce aggregated summary data."""

    def __init__(self) -> None:
        self._method_counts: Counter[str] = Counter()
        self._status_counts: Counter[int] = Counter()
        self._uri_counts: Counter[str] = Counter()
        self._user_agents: list[str] = []

    def add_request(self, http: ParsedHTTP) -> None:
        """Ingest a single parsed HTTP request/response pair."""
        if http.method:
            self._method_counts[http.method.upper()] += 1
        if http.uri:
            # Normalize URI: remove query string for aggregation
            path = urlparse(http.uri).path
            self._uri_counts[path or "/"] += 1
        if http.status_code is not None:
            self._status_counts[http.status_code] += 1
        if http.user_agent:
            self._user_agents.append(http.user_agent)

    def finalize(self) -> dict:
        """Return aggregated HTTP summary dict."""
        top_uris = self._uri_counts.most_common(TOP_HTTP_URIS)

        # Deduplicate user agents while preserving order of first appearance
        seen: set[str] = set()
        unique_agents: list[str] = []
        for ua in self._user_agents:
            if ua not in seen:
                seen.add(ua)
                unique_agents.append(ua)

        return {
            "http_method_counts": dict(self._method_counts),
            "http_status_counts": {str(k): v for k, v in self._status_counts.items()},
            "http_top_uris": [(uri, count) for uri, count in top_uris],
            "http_user_agents": unique_agents,
        }
