"""DNS profile builder: per-domain DNS analysis with entropy.

Computes per-qname query counts, success rates, average size,
Shannon entropy of subdomain labels, and TTL values.
"""

import math
import re
from collections import defaultdict
from datetime import datetime

from backend.contracts.parser_output import ParsedDNS
from backend.contracts.features import DNSProfile

BASE64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=]+$")


def _get_domain(qname: str) -> str:
    """Extract registered domain (last 2 labels)."""
    stripped = qname.rstrip(".")
    labels = stripped.split(".")
    if len(labels) <= 2:
        return stripped
    return ".".join(labels[-2:])


def _get_subdomain(qname: str) -> str:
    """Extract subdomain portion (everything before last 2 labels)."""
    labels = qname.rstrip(".").split(".")
    if len(labels) <= 2:
        return ""
    return ".".join(labels[:-2])


def _is_base64_like(text: str) -> bool:
    """Heuristic: does the string look like a base64-encoded payload?"""
    if len(text) < 12:
        return False
    if not BASE64_CHARS_RE.match(text):
        return False
    has_upper = any(c.isupper() for c in text)
    has_lower = any(c.islower() for c in text)
    has_digit = any(c.isdigit() for c in text)
    return has_upper and has_lower and has_digit


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy (bits) of a string."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    if n == 0:
        return 0.0
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return round(entropy, 4)


def _subdomain_entropy(qname: str) -> float:
    """Compute Shannon entropy of the subdomain portion of a qname.

    Uses a simple heuristic: the registered domain is the last 2 labels.
    Everything before that is the subdomain.
    Example: "abc.def.example.com" -> subdomain = "abc.def", entropy computed on "abcdef"
    """
    labels = qname.rstrip(".").split(".")
    if len(labels) <= 2:
        return 0.0
    subdomain = "".join(labels[:-2])
    return _shannon_entropy(subdomain)


def _extract_ttls(dns: ParsedDNS) -> list[int]:
    """Extract TTL values from DNS answers if available (future use).

    Current ParsedDNS does not carry TTL; returns empty list.
    """
    _ = dns  # placeholder for future TTL extraction
    return []


class DNSProfileBuilder:
    """Accumulate DNS queries and produce per-domain DNSProfile list."""

    def __init__(self) -> None:
        self._groups: dict[str, dict] = {}
        self._domain_data: dict[str, dict] = {}

    def add_query(self, dns: ParsedDNS) -> None:
        """Ingest a single parsed DNS query/response."""
        qname = dns.qname
        if qname not in self._groups:
            self._groups[qname] = {
                "count": 0,
                "qtypes": set(),
                "response_code_count": 0,
                "success_count": 0,
                "total_sizes": [],
                "src_ips": set(),
                "src_ip_counts": {},
                "timestamps": [],
                "ttls": [],
            }
        g = self._groups[qname]
        g["count"] += 1
        g["qtypes"].add(dns.qtype)
        g["src_ips"].add(str(dns.src_ip))
        g["src_ip_counts"][str(dns.src_ip)] = g["src_ip_counts"].get(str(dns.src_ip), 0) + 1
        if dns.timestamp is not None:
            g["timestamps"].append(dns.timestamp)

        if dns.query_size_bytes is not None:
            g["total_sizes"].append(dns.query_size_bytes)

        # Success: response code "0" (NOERROR)
        if dns.response_code is not None:
            g["response_code_count"] += 1  # track queries with a real response code
            if dns.response_code == "0":
                g["success_count"] += 1
        # else: query-only packet, no response code — neutral, skip

        g["ttls"].extend(_extract_ttls(dns))

        # Per-domain tracking for subdomain analysis and query frequency
        domain = _get_domain(qname)
        subdomain = _get_subdomain(qname)
        if domain not in self._domain_data:
            self._domain_data[domain] = {
                "subdomains": set(),
                "total_queries": 0,
            }
        self._domain_data[domain]["subdomains"].add(subdomain)
        self._domain_data[domain]["total_queries"] += 1

    def finalize(self) -> list[DNSProfile]:
        """Build sorted DNSProfile list with domain and IP frequency stats."""
        # Compute overall DNS time window for frequency calculations
        all_ts: list[datetime] = []
        for g in self._groups.values():
            all_ts.extend(g["timestamps"])
        if all_ts:
            duration_minutes = max((max(all_ts) - min(all_ts)).total_seconds() / 60.0, 1 / 60.0)
        else:
            duration_minutes = 1 / 60.0

        profiles = []
        for qname, g in self._groups.items():
            # Response success rate: success / packets that had a response code
            success_rate = 1.0
            if g["response_code_count"] > 0:
                success_rate = g["success_count"] / g["response_code_count"]

            avg_size = 0.0
            if g["total_sizes"]:
                avg_size = sum(g["total_sizes"]) / len(g["total_sizes"])

            # Per-domain aggregate data
            domain = _get_domain(qname)
            dd = self._domain_data.get(domain, {"subdomains": set(), "total_queries": 0})

            # query_frequency_per_ip: per src_ip, queries per minute (for this qname)
            qfp_ip = {}
            for ip, cnt in g["src_ip_counts"].items():
                qfp_ip[ip] = round(cnt / duration_minutes, 4)

            # query_frequency_per_domain: total queries for this domain per minute
            qfp_domain = round(dd["total_queries"] / duration_minutes, 4)

            # unique_subdomain_count: unique subdomain labels for this domain
            unique_sub = len(dd["subdomains"])

            # base64_ratio: fraction of subdomains that look like base64 payloads
            non_empty_subs = [s for s in dd["subdomains"] if s]
            b64_count = sum(1 for s in non_empty_subs if _is_base64_like(s))
            b64_ratio = round(b64_count / len(non_empty_subs), 4) if non_empty_subs else 0.0

            profiles.append(
                DNSProfile(
                    qname=qname,
                    query_count=g["count"],
                    unique_qtypes=sorted(g["qtypes"]),
                    subdomain_entropy=_subdomain_entropy(qname),
                    avg_query_size_bytes=round(avg_size, 2),
                    response_success_rate=round(success_rate, 4),
                    ttl_values=sorted(g["ttls"]),
                    src_ips=sorted(g["src_ips"]),
                    query_frequency_per_ip=qfp_ip,
                    query_frequency_per_domain=qfp_domain,
                    unique_subdomain_count=unique_sub,
                    base64_ratio=b64_ratio,
                )
            )

        profiles.sort(key=lambda p: p.qname)
        return profiles
