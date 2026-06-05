"""Per-PCAP report writer — JSON + Markdown output."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from contracts.findings import Finding, OverallRiskScore

from .label_store import GroundTruth


class ReportWriter:
    """Writes per-PCAP validation reports (JSON + Markdown)."""

    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)

    def _pcap_stem(self, pcap_path: str | Path) -> str:
        return Path(pcap_path).stem

    def write_json(
        self,
        pcap_path: str | Path,
        ground_truth: GroundTruth,
        findings: list[Finding],
        overall: OverallRiskScore,
        timings: dict[str, float],
        peak_memory_mb: float,
        packet_count: int,
        pcap_size_bytes: int,
    ) -> Path:
        """Write per-PCAP JSON report.

        Returns the path to the written file.
        """
        stem = self._pcap_stem(pcap_path)
        out_dir = self.output_dir / "per_pcap"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{stem}.json"

        report: dict[str, Any] = {
            "pcap_path": str(pcap_path),
            "pcap_stem": stem,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "pcap_size_bytes": pcap_size_bytes,
            "packet_count": packet_count,
            "ground_truth": {
                "attack_present": ground_truth.attack_present,
                "attack_types": ground_truth.attack_types,
                "source_ips": ground_truth.source_ips,
                "notes": ground_truth.notes,
            },
            "findings": [_finding_to_dict(f) for f in findings],
            "overall_risk": _overall_to_dict(overall),
            "performance": {
                "parse_time_s": timings.get("parse", 0.0),
                "feature_time_s": timings.get("features", 0.0),
                "rule_time_s": timings.get("rules", 0.0),
                "total_time_s": timings.get("total", 0.0),
                "throughput_pps": round(packet_count / timings.get("total", 1.0), 2)
                if timings.get("total", 0.0) > 0
                else 0.0,
                "peak_memory_mb": round(peak_memory_mb, 2),
            },
            "evaluation": {
                "has_label": ground_truth.attack_present is not None,
                "rule_ids_fired": sorted({f.rule_id for f in findings}),
            },
        }

        out_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        return out_path

    def write_markdown(
        self,
        pcap_path: str | Path,
        ground_truth: GroundTruth,
        findings: list[Finding],
        overall: OverallRiskScore,
        timings: dict[str, float],
        peak_memory_mb: float,
        packet_count: int,
        pcap_size_bytes: int,
    ) -> Path:
        """Write human-readable per-PCAP Markdown summary.

        Returns the path to the written file.
        """
        stem = self._pcap_stem(pcap_path)
        out_dir = self.output_dir / "per_pcap"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{stem}.md"

        mb_size = pcap_size_bytes / (1024 * 1024)
        total_s = timings.get("total", 0.0)
        throughput = round(packet_count / total_s, 0) if total_s > 0 else 0

        lines: list[str] = [
            f"# PCAP Report: {stem}",
            "",
            f"**File**: `{pcap_path}`",
            f"**Size**: {mb_size:.1f} MB  ({pcap_size_bytes:,} bytes)",
            f"**Packets**: {packet_count:,}",
            "",
            "## Ground Truth",
            "",
            f"- Attack present: **{ground_truth.attack_present}**",
            f"- Attack types: {ground_truth.attack_types or '_none labeled_'}",
            f"- Source IPs: {ground_truth.source_ips or '_none labeled_'}",
            f"- Notes: {ground_truth.notes or '_none_'}",
            "",
            "## Performance",
            "",
            "| Stage | Time (s) |",
            "|-------|----------|",
            f"| Parse | {timings.get('parse', 0.0):.2f} |",
            f"| Features | {timings.get('features', 0.0):.2f} |",
            f"| Rules | {timings.get('rules', 0.0):.2f} |",
            f"| **Total** | **{total_s:.2f}** |",
            f"| Throughput | {throughput:,.0f} packets/sec |",
            f"| Peak memory | {peak_memory_mb:.1f} MB |",
            "",
            "## Findings",
            "",
        ]

        if not findings:
            lines.append("_No rules fired._")
        else:
            lines.append(
                f"**{len(findings)} finding(s)** — overall risk: **{overall.weighted_score}** ({overall.severity_label.name})"
            )
            lines.append("")
            lines.append("| Rule | Severity | Risk Score | Confidence | Title |")
            lines.append("|------|----------|------------|------------|-------|")
            for f in findings:
                lines.append(
                    f"| {f.rule_id} | {f.severity.name} | {f.risk_score} | "
                    f"{f.confidence.name} | {f.title} |"
                )

        if overall.failed_rules:
            lines.extend(
                [
                    "",
                    "## Failed Rules",
                    "",
                    f"The following rules threw exceptions: {', '.join(overall.failed_rules)}",
                ]
            )

        lines.append("")  # trailing newline

        out_path.write_text("\n".join(lines), encoding="utf-8")
        return out_path


# ---- helpers ----


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": str(f.id),
        "rule_id": f.rule_id,
        "rule_name": f.rule_name,
        "rule_version": f.rule_version,
        "severity": f.severity.name,
        "confidence": f.confidence.name,
        "risk_score": f.risk_score,
        "raw_score": f.raw_score,
        "title": f.title,
        "description": f.description,
        "recommendation": f.recommendation,
        "affected_entities": f.affected_entities,
        "evidences": [
            {"key": e.key, "value": e.value, "threshold": e.threshold, "unit": e.unit}
            for e in f.evidences
        ],
    }


def _overall_to_dict(o: OverallRiskScore) -> dict[str, Any]:
    return {
        "max_score": o.max_score,
        "weighted_score": o.weighted_score,
        "severity_label": o.severity_label.name,
        "total_findings": o.total_findings,
        "findings_by_severity": o.findings_by_severity,
        "top_finding_ids": [str(fid) for fid in o.top_finding_ids],
        "failed_rules": o.failed_rules,
    }
