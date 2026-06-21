"""Tests for DNSProfileBuilder."""

import pytest

from backend.feature_extractor.dns_profiles import (
    DNSProfileBuilder,
    _get_domain,
    _get_subdomain,
    _is_base64_like,
    _shannon_entropy,
    _subdomain_entropy,
)

from .fixtures import make_parsed_dns


class TestShannonEntropy:
    """Tests for the Shannon entropy utility."""

    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy("a") == 0.0

    def test_two_chars(self):
        e = _shannon_entropy("ab")
        assert e > 0.0
        assert e == pytest.approx(1.0, rel=0.1)

    def test_repeated_char(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_dga_high_entropy(self):
        # Random-looking DGA subdomain should have high entropy
        e = _shannon_entropy("x8kf92m3nq")
        assert e > 3.0


class TestSubdomainEntropy:
    """Tests for subdomain entropy extraction."""

    def test_no_subdomain(self):
        assert _subdomain_entropy("example.com") == 0.0

    def test_single_label(self):
        e = _subdomain_entropy("abc.example.com")
        assert e > 0.0

    def test_multiple_labels(self):
        e = _subdomain_entropy("a.b.c.example.com")
        assert e > 0.0

    def test_trailing_dot(self):
        e = _subdomain_entropy("abc.example.com.")
        assert e > 0.0

    def test_dga_subdomain_high_entropy(self):
        e = _subdomain_entropy("x8kf92m3nq.example.com")
        assert e > 3.0


class TestDNSProfileBuilder:
    """Tests for DNS Profile building."""

    def test_empty(self):
        db = DNSProfileBuilder()
        profiles = db.finalize()
        assert profiles == []

    def test_single_query(self):
        db = DNSProfileBuilder()
        dns = make_parsed_dns(qname="example.com", qtype="A")
        db.add_query(dns)
        profiles = db.finalize()
        assert len(profiles) == 1
        p = profiles[0]
        assert p.qname == "example.com"
        assert p.query_count == 1
        assert "A" in p.unique_qtypes

    def test_multiple_queries_same_qname(self):
        db = DNSProfileBuilder()
        db.add_query(make_parsed_dns(qname="example.com", qtype="A"))
        db.add_query(make_parsed_dns(qname="example.com", qtype="AAAA"))
        profiles = db.finalize()
        assert len(profiles) == 1
        p = profiles[0]
        assert p.query_count == 2
        assert "A" in p.unique_qtypes
        assert "AAAA" in p.unique_qtypes

    def test_multiple_qnames(self):
        db = DNSProfileBuilder()
        db.add_query(make_parsed_dns(qname="example.com", qtype="A"))
        db.add_query(make_parsed_dns(qname="test.org", qtype="MX"))
        profiles = db.finalize()
        assert len(profiles) == 2
        assert profiles[0].qname == "example.com"
        assert profiles[1].qname == "test.org"

    def test_response_success_rate(self):
        db = DNSProfileBuilder()
        db.add_query(make_parsed_dns(qname="example.com", response_code="0"))
        db.add_query(make_parsed_dns(qname="example.com", response_code="0"))
        db.add_query(make_parsed_dns(qname="example.com", response_code="3"))  # NXDOMAIN
        profiles = db.finalize()
        p = profiles[0]
        assert p.query_count == 3
        assert p.response_success_rate == pytest.approx(0.6667)

    def test_query_size_averaging(self):
        db = DNSProfileBuilder()
        db.add_query(make_parsed_dns(qname="example.com", query_size_bytes=40))
        db.add_query(make_parsed_dns(qname="example.com", query_size_bytes=60))
        profiles = db.finalize()
        assert profiles[0].avg_query_size_bytes == 50.0

    def test_no_response_code(self):
        """Query-only packets without response code should not affect success rate."""
        db = DNSProfileBuilder()
        db.add_query(make_parsed_dns(qname="example.com", response_code=None))
        profiles = db.finalize()
        assert profiles[0].response_success_rate == 1.0  # No response code = neutral

    def test_src_ips_tracking(self):
        db = DNSProfileBuilder()
        db.add_query(make_parsed_dns(qname="example.com", src_ip="10.0.0.1"))
        db.add_query(make_parsed_dns(qname="example.com", src_ip="10.0.0.2"))
        profiles = db.finalize()
        assert "10.0.0.1" in profiles[0].src_ips
        assert "10.0.0.2" in profiles[0].src_ips


class TestDomainHelpers:
    """Tests for domain/subdomain extraction helpers."""

    def test_get_domain_two_labels(self):
        assert _get_domain("example.com") == "example.com"

    def test_get_domain_three_labels(self):
        assert _get_domain("sub.example.com") == "example.com"

    def test_get_domain_many_labels(self):
        assert _get_domain("a.b.c.example.com") == "example.com"

    def test_get_domain_trailing_dot(self):
        assert _get_domain("example.com.") == "example.com"

    def test_get_subdomain_two_labels(self):
        assert _get_subdomain("example.com") == ""

    def test_get_subdomain_three_labels(self):
        assert _get_subdomain("sub.example.com") == "sub"

    def test_get_subdomain_many_labels(self):
        assert _get_subdomain("a.b.c.example.com") == "a.b.c"


class TestBase64Detection:
    """Tests for the base64 heuristic."""

    def test_long_base64_string(self):
        assert _is_base64_like("QWxhZGRpbjpPcGVuU2VzYW1l") is True

    def test_short_string(self):
        assert _is_base64_like("abc123") is False

    def test_alphabetic_only(self):
        assert _is_base64_like("abcdefghijklm") is False  # no digits

    def test_with_special_chars(self):
        assert _is_base64_like("aGVsbG8+ d29ybGQ") is False  # has space

    def test_garbage(self):
        assert _is_base64_like("!!!@@@####$$$$") is False


class TestDNSProfileBuilderExtended:
    """Additional DNSProfileBuilder tests for new features."""

    def test_query_frequency_per_ip(self):
        """Should compute queries per minute per source IP."""
        db = DNSProfileBuilder()
        db.add_query(
            make_parsed_dns(
                qname="example.com", src_ip="10.0.0.1", timestamp="2024-01-01T00:00:00+00:00"
            )
        )
        db.add_query(
            make_parsed_dns(
                qname="example.com", src_ip="10.0.0.1", timestamp="2024-01-01T00:00:01+00:00"
            )
        )
        db.add_query(
            make_parsed_dns(
                qname="example.com", src_ip="10.0.0.2", timestamp="2024-01-01T00:00:02+00:00"
            )
        )
        profiles = db.finalize()
        assert len(profiles) == 1
        qfp = profiles[0].query_frequency_per_ip
        assert "10.0.0.1" in qfp
        assert "10.0.0.2" in qfp
        # 10.0.0.1: 2 queries over 2 sec = 2 queries in 0.0333 min ≈ 60 qpm
        assert qfp["10.0.0.1"] > 0
        # 10.0.0.2: 1 query
        assert qfp["10.0.0.2"] > 0

    def test_query_frequency_per_domain(self):
        """Should compute total queries per minute across the domain."""
        db = DNSProfileBuilder()
        db.add_query(
            make_parsed_dns(
                qname="sub1.example.com", qtype="A", timestamp="2024-01-01T00:00:00+00:00"
            )
        )
        db.add_query(
            make_parsed_dns(
                qname="sub2.example.com", qtype="AAAA", timestamp="2024-01-01T00:00:30+00:00"
            )
        )
        profiles = db.finalize()
        assert len(profiles) == 2
        # Both qnames share the same domain → same frequency
        assert profiles[0].query_frequency_per_domain > 0
        assert profiles[0].query_frequency_per_domain == profiles[1].query_frequency_per_domain

    def test_unique_subdomain_count(self):
        """Should count unique subdomains per domain."""
        db = DNSProfileBuilder()
        db.add_query(make_parsed_dns(qname="a.example.com"))
        db.add_query(make_parsed_dns(qname="b.example.com"))
        db.add_query(make_parsed_dns(qname="a.example.com"))  # duplicate subdomain
        profiles = db.finalize()
        assert len(profiles) == 2
        # 2 unique subdomains ("a", "b") for example.com
        assert profiles[0].unique_subdomain_count == 2
        assert profiles[1].unique_subdomain_count == 2

    def test_unique_subdomain_count_no_subdomain(self):
        """Domain-level qname should not count as subdomain."""
        db = DNSProfileBuilder()
        db.add_query(make_parsed_dns(qname="example.com"))
        db.add_query(make_parsed_dns(qname="sub.example.com"))
        profiles = db.finalize()
        assert len(profiles) == 2
        # 2 unique entries in subdomain set: "" and "sub"
        assert profiles[0].unique_subdomain_count == 2

    def test_base64_ratio_detects_encoded_subdomains(self):
        """Should detect base64-encoded subdomains."""
        db = DNSProfileBuilder()
        db.add_query(make_parsed_dns(qname="QWxhZGRpbjpPcGVuU2VzYW1l.example.com"))
        db.add_query(make_parsed_dns(qname="SGVsbG9Xb3JsZA.example.com"))
        db.add_query(make_parsed_dns(qname="normal.example.com"))
        profiles = db.finalize()
        assert len(profiles) == 3
        # 2 base64-like out of 3 non-empty subdomains → ratio ≈ 0.6667
        assert profiles[0].base64_ratio == pytest.approx(2 / 3, abs=0.01)

    def test_base64_ratio_normal_only(self):
        """Normal subdomains should give ratio 0.0."""
        db = DNSProfileBuilder()
        db.add_query(make_parsed_dns(qname="mail.example.com"))
        db.add_query(make_parsed_dns(qname="www.example.com"))
        profiles = db.finalize()
        assert len(profiles) == 2
        assert profiles[0].base64_ratio == 0.0
