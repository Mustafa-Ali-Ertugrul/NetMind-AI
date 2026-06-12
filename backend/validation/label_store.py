"""Ground-truth labels for PCAP validation.

Each PCAP file may have a sibling .yaml file with the same stem that
describes what attacks (if any) are present.  The YAML schema::

    pcap_file: ctu13-scenario-1.pcap
    attack_present: true
    attack_types:
      - port_scan
      - botnet_c2
    source_ips:
      - 10.0.0.5
    notes: "CTU-13 Scenario 1 — botnet IRC traffic"

A missing or incomplete YAML file is tolerated; the PCAP will still
run through the pipeline but will be excluded from precision/recall
aggregation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

GROUND_TRUTH_KEYS: set[str] = {
    "pcap_file",
    "attack_present",
    "attack_types",
    "source_ips",
    "notes",
}


@dataclass
class GroundTruth:
    """Validated ground-truth labels for a single PCAP."""

    pcap_file: str
    attack_present: bool
    attack_types: list[str] = field(default_factory=list)
    source_ips: list[str] = field(default_factory=list)
    notes: str = ""

    @classmethod
    def unknown(cls, pcap_path: Path) -> GroundTruth:
        """Return a placeholder when no label file exists."""
        return cls(
            pcap_file=pcap_path.name,
            attack_present=False,
            attack_types=[],
            source_ips=[],
            notes="(no label file — excluded from aggregate metrics)",
        )


class LabelStore:
    """Loads and caches ground-truth YAML files.

    The store looks for a ``.yaml`` file next to each PCAP with the
    same stem.  For example, ``datasets/ctu13/scenario-1.pcap`` is
    expected to have a label file ``datasets/ctu13/scenario-1.yaml``.
    """

    def __init__(self, dataset_root: str | Path) -> None:
        self.dataset_root = Path(dataset_root)

    def load(self, pcap_path: str | Path) -> GroundTruth:
        """Load ground truth for *pcap_path*.

        Returns ``GroundTruth.unknown()`` if no YAML file exists or
        if *PyYAML* is not installed.
        """
        pcap_path = Path(pcap_path)
        yaml_path = pcap_path.with_suffix(".yaml")

        if not yaml_path.is_file():
            return GroundTruth.unknown(pcap_path)

        if yaml is None:
            return GroundTruth.unknown(pcap_path)

        raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return GroundTruth.unknown(pcap_path)

        # Validate known keys
        unknown = set(raw) - GROUND_TRUTH_KEYS
        if unknown:
            import logging

            logging.getLogger("netmind.validation.label_store").warning(
                "Unknown YAML keys in %s: %s", yaml_path, sorted(unknown)
            )

        return GroundTruth(
            pcap_file=str(raw.get("pcap_file", pcap_path.name)),
            attack_present=bool(raw.get("attack_present", False)),
            attack_types=list(raw.get("attack_types", [])),
            source_ips=list(raw.get("source_ips", [])),
            notes=str(raw.get("notes", "")),
        )
