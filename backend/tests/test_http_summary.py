"""Tests for HTTPSummaryBuilder."""


from backend.feature_extractor.http_summary import HTTPSummaryBuilder

from .fixtures import make_parsed_http


class TestHTTPSummaryBuilder:
    """Tests for HTTP request aggregation."""

    def test_empty(self):
        hb = HTTPSummaryBuilder()
        summary = hb.finalize()
        assert summary["http_method_counts"] == {}
        assert summary["http_status_counts"] == {}
        assert summary["http_top_uris"] == []
        assert summary["http_user_agents"] == []

    def test_method_counting(self):
        hb = HTTPSummaryBuilder()
        hb.add_request(make_parsed_http(method="GET"))
        hb.add_request(make_parsed_http(method="GET"))
        hb.add_request(make_parsed_http(method="POST"))
        summary = hb.finalize()
        assert summary["http_method_counts"] == {"GET": 2, "POST": 1}

    def test_status_code_counting(self):
        hb = HTTPSummaryBuilder()
        hb.add_request(make_parsed_http(method="GET", uri="/", status_code=200))
        hb.add_request(make_parsed_http(method="GET", uri="/login", status_code=401))
        summary = hb.finalize()
        assert summary["http_status_counts"] == {"200": 1, "401": 1}

    def test_top_uris(self):
        hb = HTTPSummaryBuilder()
        for _ in range(5):
            hb.add_request(make_parsed_http(method="GET", uri="/index.html"))
        for _ in range(3):
            hb.add_request(make_parsed_http(method="GET", uri="/login"))
        summary = hb.finalize()
        top = summary["http_top_uris"]
        assert top[0] == ("/index.html", 5)
        assert top[1] == ("/login", 3)

    def test_uri_query_string_normalization(self):
        """Query strings should be stripped for aggregation."""
        hb = HTTPSummaryBuilder()
        hb.add_request(make_parsed_http(method="GET", uri="/search?q=hello"))
        hb.add_request(make_parsed_http(method="GET", uri="/search?q=world"))
        summary = hb.finalize()
        assert summary["http_top_uris"] == [("/search", 2)]

    def test_user_agent_deduplication(self):
        hb = HTTPSummaryBuilder()
        hb.add_request(make_parsed_http(method="GET", uri="/", user_agent="Mozilla/5.0"))
        hb.add_request(make_parsed_http(method="GET", uri="/", user_agent="Mozilla/5.0"))
        hb.add_request(make_parsed_http(method="GET", uri="/", user_agent="curl/7.0"))
        summary = hb.finalize()
        assert len(summary["http_user_agents"]) == 2
        assert "Mozilla/5.0" in summary["http_user_agents"]
        assert "curl/7.0" in summary["http_user_agents"]

    def test_missing_user_agent(self):
        hb = HTTPSummaryBuilder()
        hb.add_request(make_parsed_http(method="GET", uri="/", user_agent=None))
        summary = hb.finalize()
        assert summary["http_user_agents"] == []
