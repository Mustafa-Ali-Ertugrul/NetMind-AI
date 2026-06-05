"""Cross-PCAP metric aggregation.

Computes per-rule confusion matrix and derived metrics
(precision, recall, F1, false-positive rate) across all labeled PCAPs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class ConfusionMatrix:
    """Per-rule confusion matrix across all labeled PCAPs."""

    tp: int = 0  # attack PCAP where rule fired
    fp: int = 0  # benign PCAP where rule fired
    tn: int = 0  # benign PCAP where rule did NOT fire
    fn: int = 0  # attack PCAP where rule did NOT fire

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        """TP / (TP + FP).  0 if no positive predictions."""
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        """TP / (TP + FN).  0 if no actual positives."""
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall.  0 if either is 0."""
        p = self.precision
        r = self.recall
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)

    @property
    def fpr(self) -> float:
        """False-positive rate = FP / (FP + TN).  0 if no actual negatives."""
        denom = self.fp + self.tn
        return self.fp / denom if denom > 0 else 0.0

    @property
    def accuracy(self) -> float:
        """(TP + TN) / total."""
        if self.total == 0:
            return 0.0
        return (self.tp + self.tn) / self.total


@dataclass
class RuleMetrics:
    """Aggregated metrics for one detection rule."""

    rule_id: str
    rule_name: str
    matrix: ConfusionMatrix = field(default_factory=ConfusionMatrix)
    labeled_pcaps: int = 0

    @property
    def metrics(self) -> dict[str, float]:
        return {
            "precision": round(self.matrix.precision, 4),
            "recall": round(self.matrix.recall, 4),
            "f1": round(self.matrix.f1, 4),
            "fpr": round(self.matrix.fpr, 4),
            "accuracy": round(self.matrix.accuracy, 4),
            "tp": self.matrix.tp,
            "fp": self.matrix.fp,
            "tn": self.matrix.tn,
            "fn": self.matrix.fn,
        }


# Well-known rule IDs for the current pipeline
KNOWN_RULES: dict[str, str] = {
    "NET-001": "Port Scan Detection",
    "NET-002": "DNS Tunneling Detection",
    "NET-003": "FTP Brute Force Detection",
    "NET-004": "SMTP Abuse Detection",
}


# Mapping from ground-truth attack_types to Rule IDs
# Each attack type can map to one or more rules that are expected to fire.
ATTACK_TYPE_TO_RULES: dict[str, list[str]] = {
    "port_scan": ["NET-001"],
    "dns_tunneling": ["NET-002"],
    "ftp_brute_force": ["NET-003"],
    "smtp_abuse": ["NET-004"],
    # future:
    "botnet_c2": ["NET-001", "NET-002"],  # many botnets scan or use DNS
}


class MetricCalculator:
    """Aggregates per-PCAP results into per-rule confusion matrices."""

    def __init__(self) -> None:
        self.rules: dict[str, RuleMetrics] = {}

    def _ensure_rule(self, rule_id: str) -> RuleMetrics:
        if rule_id not in self.rules:
            self.rules[rule_id] = RuleMetrics(
                rule_id=rule_id,
                rule_name=KNOWN_RULES.get(rule_id, "Unknown"),
            )
        return self.rules[rule_id]

    def add_result(
        self,
        attack_present: bool,
        rule_ids_fired: set[str],
        attack_types: list[str],
    ) -> None:
        """Feed one PCAP result into the aggregator.

        Args:
            attack_present: Whether the PCAP is labeled as malicious.
            rule_ids_fired: Set of rule IDs that fired for this PCAP.
            attack_types: Attack types from the label.
        """
        all_rule_ids = set(KNOWN_RULES)
        
        # Determine which rules were EXPECTED to fire
        expected_rules: set[str] = set()
        if attack_present:
            for atype in attack_types:
                for rid in ATTACK_TYPE_TO_RULES.get(atype, []):
                    expected_rules.add(rid)

        for rid in all_rule_ids:
            rm = self._ensure_rule(rid)
            fired = rid in rule_ids_fired
            expected = rid in expected_rules
            
            if expected:
                # This rule was expected to fire
                if fired:
                    rm.matrix.tp += 1
                else:
                    rm.matrix.fn += 1
            else:
                # This rule was NOT expected to fire (either benign PCAP or different attack)
                if fired:
                    rm.matrix.fp += 1
                else:
                    rm.matrix.tn += 1
            
            rm.labeled_pcaps += 1

    def summary(self) -> dict[str, Any]:
        """Return aggregate metrics as a plain dict (ready for JSON)."""
        return {
            "generated_at": __import__("datetime")
            .datetime.now(__import__("datetime").timezone.utc)
            .isoformat(),
            "rules": {
                rid: {
                    "rule_id": rm.rule_id,
                    "rule_name": rm.rule_name,
                    "labeled_pcaps": rm.labeled_pcaps,
                    **rm.metrics,
                }
                for rid, rm in sorted(self.rules.items())
            },
            "overall": _overall_metrics(self.rules),
        }

    def write_markdown(self, path: str | Path) -> None:
        """Write a human-readable Markdown aggregate report."""
        lines: list[str] = [
            "# NetMind AI — Validation Aggregate Report",
            "",
            f"Generated: {__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()}",
            "",
            "## Per-Rule Metrics",
            "",
            "| Rule | Labeled PCAPs | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Accuracy |",
            "|------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|",
        ]

        for rid in sorted(self.rules):
            rm = self.rules[rid]
            mx = rm.matrix
            lines.append(
                f"| {rm.rule_id} ({rm.rule_name}) "
                f"| {rm.labeled_pcaps} "
                f"| {mx.tp} | {mx.fp} | {mx.tn} | {mx.fn} "
                f"| {mx.precision:.3f} | {mx.recall:.3f} | {mx.f1:.3f} "
                f"| {mx.fpr:.3f} | {mx.accuracy:.3f} |"
            )

        ov = _overall_metrics(self.rules)
        lines.extend(
            [
                "",
                "## Overall",
                "",
                f"- **Labeled PCAPs**: {ov['labeled_pcaps']}",
                f"- **Macro avg precision**: {ov['macro_precision']:.4f}",
                f"- **Macro avg recall**: {ov['macro_recall']:.4f}",
                f"- **Macro avg F1**: {ov['macro_f1']:.4f}",
                f"- **Total TP**: {ov['total_tp']}",
                f"- **Total FP**: {ov['total_fp']}",
                f"- **Total TN**: {ov['total_tn']}",
                f"- **Total FN**: {ov['total_fn']}",
                "",
                "---",
                "",
                "_Method: per-rule confusion matrix across all PCAPs with "
                "ground-truth labels. PCAPs without labels are excluded._",
                "",
            ]
        )
        Path(path).write_text("\n".join(lines), encoding="utf-8")

    def write_json(self, path: str | Path) -> None:
        """Write aggregate report as JSON."""
        Path(path).write_text(json.dumps(self.summary(), indent=2, default=str), encoding="utf-8")


def _overall_metrics(rules: dict[str, RuleMetrics]) -> dict[str, Any]:
    """Macro-averaged overall metrics."""
    if not rules:
        return {
            "labeled_pcaps": 0,
            "macro_precision": 0.0,
            "macro_recall": 0.0,
            "macro_f1": 0.0,
            "total_tp": 0,
            "total_fp": 0,
            "total_tn": 0,
            "total_fn": 0,
        }

    n = len(rules)
    rule_list = list(rules.values())
    total_tp = sum(r.matrix.tp for r in rule_list)
    total_fp = sum(r.matrix.fp for r in rule_list)
    total_tn = sum(r.matrix.tn for r in rule_list)
    total_fn = sum(r.matrix.fn for r in rule_list)

    return {
        "labeled_pcaps": max(r.labeled_pcaps for r in rule_list),
        "macro_precision": round(sum(r.matrix.precision for r in rule_list) / n, 4),
        "macro_recall": round(sum(r.matrix.recall for r in rule_list) / n, 4),
        "macro_f1": round(sum(r.matrix.f1 for r in rule_list) / n, 4),
        "total_tp": total_tp,
        "total_fp": total_fp,
        "total_tn": total_tn,
        "total_fn": total_fn,
    }
