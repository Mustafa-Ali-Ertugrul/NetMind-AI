"""Headless validation runner.

Usage::

    python -m validation.run \\
        --dataset-root ../../datasets \\
        --output        ../reports \\
        --max-pcaps     2

Each PCAP is parsed, features extracted, and rules evaluated.  Timing
and memory usage are recorded per PCAP.  Results are written to the
output directory as per-PCAP JSON + Markdown, plus an aggregate report.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the project root (NetMind-AI/) is on sys.path so that
# ``from backend.xxx`` resolves regardless of how this module was loaded.
_project_root = Path(__file__).resolve().parent.parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

import argparse
import logging
import os
import shutil
import time
import tracemalloc
from hashlib import sha256
from typing import Any
from uuid import UUID

from backend.contracts.features import AggregatedFeatures
from backend.contracts.findings import Finding, OverallRiskScore
from backend.contracts.parser_output import ParsedProtocols

from backend.feature_extractor import FeatureExtractor, extract_features
from backend.protocol_parser import ProtocolParser, TsharkError
from backend.rule_engine import RuleEngine

from .aggregate import MetricCalculator
from .label_store import LabelStore
from .report import ReportWriter

logger = logging.getLogger("netmind.validation.runner")

SUPPORTED_EXTENSIONS = {".pcap", ".pcapng"}

# ---------------------------------------------------------------------------
# Deterministic PCAP ID
# ---------------------------------------------------------------------------


def _pcap_id_from_path(path: Path) -> UUID:
    """Deterministic UUID derived from the canonical path."""
    canonical = str(path.resolve()).encode("utf-8")
    digest = sha256(canonical).digest()[:16]
    return UUID(bytes=digest)


# ---------------------------------------------------------------------------
# PCAP discovery
# ---------------------------------------------------------------------------


def _discover_pcaps(
    dataset_root: Path,
    dataset_filter: list[str] | None,
    max_pcaps: int | None,
) -> list[Path]:
    """Walk *dataset_root* and return sorted PCAP file paths.

    Only first-level subdirectories (CICIDS2017, CTU-13, ...) are
    scanned.  If *dataset_filter* is given, only those subdirectory
    names are included.  If *max_pcaps* is set, return at most that
    many files (for smoke testing).
    """
    pcaps: list[Path] = []

    if not dataset_root.is_dir():
        logger.warning("Dataset root %s does not exist — no PCAPs to validate.", dataset_root)
        return pcaps

    for subdir in sorted(dataset_root.iterdir()):
        if not subdir.is_dir():
            continue
        if dataset_filter and subdir.name not in dataset_filter:
            continue
        for child in sorted(subdir.iterdir()):
            if child.suffix.lower() in SUPPORTED_EXTENSIONS:
                pcaps.append(child)

    if max_pcaps is not None and max_pcaps > 0:
        # Take evenly across datasets where possible
        if len(pcaps) > max_pcaps:
            step = len(pcaps) / max_pcaps
            sampled: list[Path] = []
            for i in range(max_pcaps):
                idx = int(i * step)
                if idx < len(pcaps) and pcaps[idx] not in {p.resolve() for p in sampled}:
                    sampled.append(pcaps[idx])
            if len(sampled) < max_pcaps:
                # fall back to simple slice
                sampled = pcaps[:max_pcaps]
            pcaps = sampled

    return pcaps


# ---------------------------------------------------------------------------
# Validation runner
# ---------------------------------------------------------------------------


class ValidationRunner:
    """Orchestrates PCAP validation end-to-end."""

    def __init__(
        self,
        dataset_root: str | Path,
        output_dir: str | Path,
        tshark_path: str | None = None,
        max_pcaps: int | None = None,
        dataset_filter: list[str] | None = None,
        skip_unsupervised: bool = True,
    ) -> None:
        self.dataset_root = Path(dataset_root)
        self.output_dir = Path(output_dir)
        self.tshark_path = tshark_path
        self.max_pcaps = max_pcaps
        self.dataset_filter = dataset_filter
        self.skip_unsupervised = skip_unsupervised

        self.label_store = LabelStore(self.dataset_root)
        self.report_writer = ReportWriter(self.output_dir)
        self.metric_calculator = MetricCalculator()

    def run(self) -> int:
        """Run validation on all discovered PCAPs.

        Returns the number of PCAPs successfully processed.
        """
        pcaps = _discover_pcaps(self.dataset_root, self.dataset_filter, self.max_pcaps)
        if not pcaps:
            logger.warning("No PCAP files found under %s.", self.dataset_root)
            return 0

        # ---- Pipeline components (fresh per run) ----
        extractor = FeatureExtractor()
        engine = RuleEngine()

        processed = 0
        for pcap_path in pcaps:
            success = self._process_one(pcap_path, extractor, engine)
            if success:
                processed += 1

        # ---- Aggregate ----
        self._write_aggregate()
        logger.info("Validation complete: %d / %d PCAPs processed.", processed, len(pcaps))
        return processed

    # ------------------------------------------------------------------
    # Single-PCAP processing
    # ------------------------------------------------------------------

    def _process_one(
        self,
        pcap_path: Path,
        extractor: FeatureExtractor,
        engine: RuleEngine,
    ) -> bool:
        """Run the full pipeline on one PCAP and write its reports.

        Returns True on success, False on failure.
        """
        logger.info("Processing %s ...", pcap_path)
        timings: dict[str, float] = {}
        peak_memory_mb = 0.0
        packet_count = 0
        pcap_size_bytes = pcap_path.stat().st_size

        ground_truth = self.label_store.load(pcap_path)

        try:
            # ---- Parse ----
            tracemalloc.start()
            t0 = time.perf_counter()
            pcap_id = _pcap_id_from_path(pcap_path)
            parser = ProtocolParser(tshark_path=self.tshark_path)
            parsed: ParsedProtocols = parser.parse_pcap(pcap_path, pcap_id)
            t1 = time.perf_counter()
            timings["parse"] = round(t1 - t0, 4)
            packet_count = len(parsed.packets)

            # ---- Features ----
            t2 = time.perf_counter()
            features: AggregatedFeatures = extractor.extract(parsed)
            t3 = time.perf_counter()
            timings["features"] = round(t3 - t2, 4)

            # ---- Rules ----
            t4 = time.perf_counter()
            findings, overall = engine.analyze(features)
            t5 = time.perf_counter()
            timings["rules"] = round(t5 - t4, 4)

            timings["total"] = round(t5 - t0, 4)

            # Memory
            _current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            peak_memory_mb = peak / (1024 * 1024)

        except TsharkError as exc:
            logger.error("Tshark error for %s: %s", pcap_path, exc)
            print(f"  ERROR: tshark failed for {pcap_path.name} — skipping.", file=sys.stderr)
            tracemalloc.stop()
            return False
        except FileNotFoundError as exc:
            logger.error("File not found: %s", exc)
            print(f"  ERROR: {exc}", file=sys.stderr)
            tracemalloc.stop()
            return False
        except Exception:
            logger.exception("Unexpected error processing %s", pcap_path)
            print(f"  ERROR: unexpected error for {pcap_path.name} — skipping.", file=sys.stderr)
            tracemalloc.stop()
            return False

        # ---- Write per-PCAP reports ----
        self.report_writer.write_json(
            pcap_path,
            ground_truth,
            findings,
            overall,
            timings,
            peak_memory_mb,
            packet_count,
            pcap_size_bytes,
        )
        self.report_writer.write_markdown(
            pcap_path,
            ground_truth,
            findings,
            overall,
            timings,
            peak_memory_mb,
            packet_count,
            pcap_size_bytes,
        )

        # ---- Feed into aggregate ----
        if ground_truth.notes and "no label file" in ground_truth.notes:
            logger.info("  %s — skipped from aggregate (no label).", pcap_path.name)
        else:
            self.metric_calculator.add_result(
                attack_present=ground_truth.attack_present,
                rule_ids_fired={f.rule_id for f in findings},
                attack_types=ground_truth.attack_types,
            )

        self._log_performance(pcap_path, packet_count, timings, peak_memory_mb)
        print(
            f"  OK: {pcap_path.name} — {len(findings)} finding(s), overall {overall.weighted_score} ({overall.severity_label.name})"
        )
        return True

    # ------------------------------------------------------------------
    # Aggregate output
    # ------------------------------------------------------------------

    def _write_aggregate(self) -> None:
        """Write cross-PCAP aggregate reports."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        md_path = self.output_dir / "validation_report.md"
        json_path = self.output_dir / "validation_report.json"

        self.metric_calculator.write_markdown(md_path)
        self.metric_calculator.write_json(json_path)

        logger.info("Aggregate report written to %s and %s", md_path, json_path)

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _log_performance(
        pcap_path: Path,
        packet_count: int,
        timings: dict[str, float],
        peak_memory_mb: float,
    ) -> None:
        total_s = timings.get("total", 0.0)
        throughput = packet_count / total_s if total_s > 0 else 0.0
        mb_size = pcap_path.stat().st_size / (1024 * 1024)

        logger.info(
            "  %s: %d packets, %.1f MB, parse=%.1fs feat=%.1fs rules=%.1fs "
            "total=%.1fs (%.0f pps), mem=%.1f MB",
            pcap_path.name,
            packet_count,
            mb_size,
            timings.get("parse", 0.0),
            timings.get("features", 0.0),
            timings.get("rules", 0.0),
            total_s,
            throughput,
            peak_memory_mb,
        )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="NetMind AI — Validation Harness (Phase 3.5)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m validation.run --dataset-root ../../datasets --output ../reports\n"
            "  python -m validation.run --max-pcaps 2  # smoke test\n"
            "  python -m validation.run --datasets ctu13  # single dataset\n"
        ),
    )
    parser.add_argument(
        "--dataset-root",
        default=os.environ.get("NETMIND_DATASET_ROOT", str(Path.cwd() / "datasets")),
        help="Root directory containing dataset sub-folders (default: ./datasets)",
    )
    parser.add_argument(
        "--output",
        default=os.environ.get("NETMIND_REPORT_DIR", str(Path.cwd() / "reports")),
        help="Output directory for reports (default: ./reports)",
    )
    parser.add_argument(
        "--datasets",
        nargs="*",
        default=None,
        help="Filter: only process these dataset sub-folders (e.g., cicids2017 ctu13)",
    )
    parser.add_argument(
        "--max-pcaps",
        type=int,
        default=None,
        help="Maximum number of PCAPs to process (smoke-test mode)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set logging level (default: INFO)",
    )
    return parser.parse_args(argv)


def main() -> None:
    """CLI entry point for ``python -m validation.run``."""
    args = _parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    runner = ValidationRunner(
        dataset_root=args.dataset_root,
        output_dir=args.output,
        max_pcaps=args.max_pcaps,
        dataset_filter=args.datasets,
    )
    processed = runner.run()

    if processed == 0:
        logger.warning("No PCAPs were processed successfully.")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
