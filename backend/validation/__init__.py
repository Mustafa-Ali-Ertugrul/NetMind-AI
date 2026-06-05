"""NetMind AI — Phase 3.5 Validation Harness.

Headless PCAP-replay validation that evaluates the existing pipeline
(tshark → parser → features → rules → findings) against labeled
datasets (CICIDS2017, CTU-13, Stratosphere, MAWILab).

Usage::

    python -m validation.run \\
        --dataset-root ../../datasets \\
        --output        ../reports \\
        --max-pcaps     2          # smoke-test mode

Produces per-PCAP JSON + Markdown reports and a cross-PCAP aggregate
report with per-rule precision, recall, F1, and performance metrics.
"""

from .aggregate import MetricCalculator
from .label_store import LabelStore, GroundTruth
from .report import ReportWriter
from .runner import ValidationRunner

__all__ = [
    "MetricCalculator",
    "LabelStore",
    "GroundTruth",
    "ReportWriter",
    "ValidationRunner",
]
