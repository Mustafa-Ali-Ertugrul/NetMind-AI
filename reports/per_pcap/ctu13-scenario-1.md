# PCAP Report: ctu13-scenario-1

**File**: `..\datasets\ctu13\ctu13-scenario-1.pcap`
**Size**: 55.6 MB  (58,266,506 bytes)
**Packets**: 322,244

## Ground Truth

- Attack present: **True**
- Attack types: ['botnet_c2', 'port_scan']
- Source IPs: ['147.32.84.165']
- Notes: CTU-13 Scenario 1 — Neris botnet IRC

## Performance

| Stage | Time (s) |
|-------|----------|
| Parse | 132.19 |
| Features | 19.08 |
| Rules | 0.01 |
| **Total** | **151.28** |
| Throughput | 2,130 packets/sec |
| Peak memory | 661.5 MB |

## Findings

**17 finding(s)** — overall risk: **22** (LOW)

| Rule | Severity | Risk Score | Confidence | Title |
|------|----------|------------|------------|-------|
| NET-001 | CRITICAL | 55 | MEDIUM | Port scan detected from 173.192.170.88 |
| NET-001 | CRITICAL | 55 | MEDIUM | Port scan detected from 174.133.57.141 |
| NET-001 | MEDIUM | 11 | MEDIUM | Port scan detected from 174.36.246.56 |
| NET-001 | MEDIUM | 9 | MEDIUM | Port scan detected from 195.113.232.82 |
| NET-001 | MEDIUM | 7 | MEDIUM | Port scan detected from 195.113.232.83 |
| NET-001 | MEDIUM | 9 | MEDIUM | Port scan detected from 195.113.232.88 |
| NET-001 | MEDIUM | 10 | MEDIUM | Port scan detected from 208.73.210.29 |
| NET-001 | CRITICAL | 55 | MEDIUM | Port scan detected from 212.117.171.138 |
| NET-001 | HIGH | 18 | MEDIUM | Port scan detected from 31.192.109.167 |
| NET-001 | MEDIUM | 10 | MEDIUM | Port scan detected from 50.22.198.84 |
| NET-001 | MEDIUM | 7 | MEDIUM | Port scan detected from 64.236.79.229 |
| NET-001 | MEDIUM | 9 | MEDIUM | Port scan detected from 65.55.196.251 |
| NET-001 | MEDIUM | 11 | MEDIUM | Port scan detected from 67.214.158.5 |
| NET-001 | MEDIUM | 7 | MEDIUM | Port scan detected from 74.125.232.217 |
| NET-001 | MEDIUM | 7 | MEDIUM | Port scan detected from 74.222.3.26 |
| NET-001 | MEDIUM | 12 | MEDIUM | Port scan detected from 98.126.71.122 |
| NET-002 | MEDIUM | 32 | MEDIUM | Potential DNS tunneling detected:  |
