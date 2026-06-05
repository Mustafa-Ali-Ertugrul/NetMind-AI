"""Constants and thresholds for the Feature Extraction Layer."""

EXTRACTOR_VERSION = "1.0.0"

# Number of top flow deviations to include
TOP_FLOW_DEVIATIONS = 20

# Number of top HTTP URIs to include
TOP_HTTP_URIS = 20

# Port-scan detection thresholds
PORT_SCAN_PORT_THRESHOLD = 20  # ≥ N distinct ports to a single dst_ip → suspect
PORT_SCAN_RATIO_THRESHOLD = 0.7  # ≥ 70% of flows to same dst must be suspect

# Burst detection
BURST_MULTIPLIER = 5.0  # flow bps > N× global baseline → burst flagged

# Failure detection
# Minimum payload bytes expected for a successful TCP handshake + exchange
# (SYN + SYN-ACK + ACK + minimal data ≈ 200 B)
FAILURE_PAYLOAD_BYTES_THRESHOLD = 200

# Rate-limit window
RATE_WINDOW_SECONDS = 1.0
