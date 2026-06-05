"""FROZEN 2026-06-05 — Threshold baseline for PCAP validation.

This file is a frozen copy of rule_engine/thresholds.py at the time of
Phase 3.5 validation.  It MUST NOT be modified without re-running the
full validation suite and updating this header date.

Any tuning after validation must produce a new baseline and a new
validation report, so that before/after metrics are comparable.
"""

# Port Scan Rule
PORT_SCAN_SUSPECT_RATIO_MIN = 0.7
PORT_SCAN_CPM_LOW = 50.0
PORT_SCAN_CPM_MEDIUM = 150.0
PORT_SCAN_CPM_HIGH = 600.0
PORT_SCAN_PORTS_MEDIUM = 20
PORT_SCAN_PORTS_HIGH = 50
PORT_SCAN_PORTS_CRITICAL = 200

# DNS Tunneling Rule  (all frequencies in queries per minute)
DNS_BASE64_RATIO_SUSPECT = 0.3
DNS_BASE64_RATIO_HIGH = 0.7
DNS_SUBDOMAIN_COUNT_SUSPECT = 20
DNS_SUBDOMAIN_COUNT_HIGH = 50
DNS_ENTROPY_SUSPECT = 4.0
DNS_ENTROPY_HIGH = 5.5
DNS_QUERY_FREQ_PER_DOMAIN_SUSPECT = 60.0
DNS_QUERY_FREQ_PER_DOMAIN_HIGH = 200.0
DNS_QUERY_FREQ_PER_IP_SUSPECT = 20.0

# FTP Brute Force Rule
FTP_FAILED_AUTH_RATIO_SUSPECT = 0.7
FTP_FAILED_AUTH_COUNT_MIN = 3
FTP_AUTH_RATE_SUSPECT = 0.3
FTP_AUTH_RATE_HIGH = 1.0

# SMTP Abuse Rule
SMTP_FAILED_AUTH_COUNT_SUSPECT = 3
SMTP_UNIQUE_RECIPIENTS_SUSPECT = 25
SMTP_UNIQUE_RECIPIENTS_HIGH = 100
SMTP_MESSAGE_COUNT_SUSPECT = 5
SMTP_MESSAGE_COUNT_HIGH = 20
