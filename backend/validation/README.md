# NetMind AI — Validation Harness (Phase 3.5)

Headless PCAP-replay validation for the NetMind AI detection pipeline.

## Purpose

The validation harness evaluates the existing pipeline (tshark → parser →
feature extractor → rule engine) against **labeled real-world PCAP datasets**
so that:

- Per-rule **precision, recall, F1, and FPR** are measured.
- Pipeline **performance metrics** (throughput, parse/feature/rule time, peak
  memory) are captured.
- Threshold tuning is backed by data, not guesswork.
- Regression is caught before shipping.

The harness **does not** modify any pipeline code.  It only reads, runs, and
reports.

## Directory Layout

```
NetMind-AI/
├── backend/validation/       ← this package
├── datasets/                 ← PCAP files (gitignored, download separately)
│   ├── cicids2017/
│   ├── ctu13/
│   ├── stratosphere/
│   └── mawilab/
├── reports/                  ← validation output (gitignored)
│   ├── per_pcap/             ← individual JSON + MD reports
│   ├── validation_report.md  ← aggregate summary (Markdown)
│   └── validation_report.json ← aggregate summary (JSON)
└── ...
```

## Requirements

1. **tshark** (from [Wireshark](https://www.wireshark.org/)) must be installed
   and on PATH, or pointed to via the `NETMIND_TSHARK_PATH` environment
   variable.

2. **Python** 3.11+ with the project's virtual environment activated (the
   usual `venv` at `C:\Users\Ali\AppData\Local\hermes\hermes-agent\venv`).

3. **PyYAML** for loading ground-truth label files (optional — missing labels
   are tolerated).

## Datasets

### Download

Place PCAP files in the correct `datasets/<source>/` subdirectory.  Each
PCAP may have a sibling `.yaml` file with ground-truth labels (see
[Label Files](#label-files) below).

Recommended datasets for first validation:

| Source | PCAP | Size | Label |
|--------|------|------|-------|
| CICIDS2017 | Monday-Benign.pcap | ~11 GB | Benign |
| CICIDS2017 | Friday-WorkingHours.pcap | ~8 GB | Attacks |
| CTU-13 | ctu13-scenario-1.pcap | ~118 MB | Botnet |
| CTU-13 | ctu13-scenario-8.pcap | ~205 MB | Botnet |
| Stratosphere | capture-1-android-benchmark.pcap | ~15 MB | Malware |
| MAWILab | mawi-sample.pcap | ~100 MB | Mixed |

> The manifest in `manifest.py` contains these entries with expected
> attack types.  Add more PCAPs as needed.

### Label Files

Each PCAP can have a YAML sibling with the same stem:

```yaml
# datasets/ctu13/ctu13-scenario-1.yaml
pcap_file: ctu13-scenario-1.pcap
attack_present: true
attack_types:
  - port_scan
  - botnet_c2
source_ips:
  - 10.0.0.5
notes: "CTU-13 Scenario 1 — Neris botnet IRC traffic"
```

If no label file exists the PCAP is still processed but excluded from
precision/recall aggregation.

## Usage

```bash
# Activate the venv first
cd backend

# Full validation
python -m validation.run \
    --dataset-root ../datasets \
    --output       ../reports

# Smoke test (first 2 PCAPs)
python -m validation.run \
    --dataset-root ../datasets \
    --output       ../reports \
    --max-pcaps    2

# Single dataset
python -m validation.run \
    --dataset-root ../datasets \
    --datasets     ctu13

# Custom tshark path
set NETMIND_TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe
python -m validation.run \
    --dataset-root ../datasets \
    --output       ../reports
```

## Output

### Per-PCAP (`reports/per_pcap/<stem>.json` / `.md`)

Each PCAP produces:

- **Performance**: parse time, feature time, rule time, total time,
  throughput (packets/sec), peak memory (MB).
- **Ground truth**: attack present, attack types, source IP labels.
- **Findings**: every finding produced by the rule engine.
- **Evaluation**: rule IDs that fired, whether the PCAP was labeled.

### Aggregate (`reports/validation_report.json` / `.md`)

Cross-PCAP metrics:

- Per-rule **confusion matrix** (TP, FP, TN, FN).
- Per-rule **precision, recall, F1, FPR, accuracy**.
- Macro-averaged overall metrics.

## Frozen Thresholds

This validation run uses `thresholds_baseline.py` — a frozen copy of the
live `rule_engine/thresholds.py` at validation time.  This ensures:

1. **Reproducibility**: re-running validation with the same baseline gives
   the same results.
2. **Comparability**: before/after tuning comparisons are fair.

When thresholds are tuned, update the baseline file, re-run validation,
and compare the two reports.

## Adding a New Dataset

1. Create a subdirectory under `datasets/`, e.g., `datasets/my-dataset/`.
2. Place PCAP files there.
3. Add a YAML label file for each PCAP (optional but recommended).
4. Optionally add an entry to `manifest.py` for documentation.
5. Run validation — the harness auto-discovers PCAPs in any subdirectory.

## Metrics Glossary

| Metric | Formula | Meaning |
|--------|---------|---------|
| TP | — | Attack PCAP where the rule fired (correct detection). |
| FP | — | Benign PCAP where the rule fired (false alarm). |
| TN | — | Benign PCAP where the rule did **not** fire. |
| FN | — | Attack PCAP where the rule did **not** fire (miss). |
| Precision | TP / (TP + FP) | How often the rule's alert is correct. |
| Recall | TP / (TP + FN) | How many attacks the rule catches. |
| F1 | 2·P·R / (P + R) | Harmonic mean of precision and recall. |
| FPR | FP / (FP + TN) | False alarm rate among benign traffic. |
| Throughput | packets / total_time | Processing speed (packets/sec). |
