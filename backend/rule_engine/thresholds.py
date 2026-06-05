"""Thresholds and constants for Rule Engine detection rules.

Naming convention:
  _SUSPECT  = lowest threshold to be considered potentially suspicious
  _MEDIUM   = MEDIUM severity threshold
  _HIGH     = HIGH severity threshold
  _CRITICAL = CRITICAL severity threshold

Unless otherwise noted, all DNS query frequency thresholds are in
**queries per minute** (qpm), matching the Feature Extractor output scale.
"""

# Port Scan Rule
PORT_SCAN_SUSPECT_RATIO_MIN = 0.7  # extractor's failed-connection ratio flag
PORT_SCAN_CPM_LOW = 50.0  # connections per minute → lowest gate
PORT_SCAN_CPM_MEDIUM = 150.0  # connections per minute → MEDIUM
PORT_SCAN_CPM_HIGH = 600.0  # connections per minute → HIGH
PORT_SCAN_PORTS_MEDIUM = 20  # aligned with extractor PORT_SCAN_PORT_THRESHOLD
PORT_SCAN_PORTS_HIGH = 50
PORT_SCAN_PORTS_CRITICAL = 200

# DNS Tunneling Rule  (all frequencies in queries per minute)
DNS_BASE64_RATIO_SUSPECT = 0.3
DNS_BASE64_RATIO_HIGH = 0.7
DNS_SUBDOMAIN_COUNT_SUSPECT = 20
DNS_SUBDOMAIN_COUNT_HIGH = 50
DNS_ENTROPY_SUSPECT = 4.0
DNS_ENTROPY_HIGH = 5.5
DNS_QUERY_FREQ_PER_DOMAIN_SUSPECT = 60.0  # qpm (≈ 1 query/sec)
DNS_QUERY_FREQ_PER_DOMAIN_HIGH = 200.0  # qpm
DNS_QUERY_FREQ_PER_IP_SUSPECT = 20.0  # qpm

# FTP Brute Force Rule
FTP_FAILED_AUTH_RATIO_SUSPECT = 0.7
FTP_FAILED_AUTH_COUNT_MIN = 3
FTP_AUTH_RATE_SUSPECT = 0.3
FTP_AUTH_RATE_HIGH = 1.0

# SMTP Abuse Rule
SMTP_FAILED_AUTH_COUNT_SUSPECT = 3
SMTP_UNIQUE_RECIPIENTS_SUSPECT = 25  # avoid newsletter FPs
SMTP_UNIQUE_RECIPIENTS_HIGH = 100
SMTP_MESSAGE_COUNT_SUSPECT = 5
SMTP_MESSAGE_COUNT_HIGH = 20
