# PCAP Report: capture-1-android-benchmark

**File**: `..\datasets\stratosphere\capture-1-android-benchmark.pcap`
**Size**: 1.2 MB  (1,214,633 bytes)
**Packets**: 2,233

## Ground Truth

- Attack present: **True**
- Attack types: ['malware_rat', 'command_and_control']
- Source IPs: ['147.32.83.245']
- Notes: Stratosphere Android Mischief Dataset — cli_AndroRAT

## Performance

| Stage | Time (s) |
|-------|----------|
| Parse | 0.91 |
| Features | 0.11 |
| Rules | 0.00 |
| **Total** | **1.02** |
| Throughput | 2,191 packets/sec |
| Peak memory | 5.6 MB |

## Findings

**1 finding(s)** — overall risk: **52** (HIGH)

| Rule | Severity | Risk Score | Confidence | Title |
|------|----------|------------|------------|-------|
| NET-001 | CRITICAL | 52 | MEDIUM | Port scan detected from 104.152.52.23 |
