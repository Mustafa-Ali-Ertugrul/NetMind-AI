"""Dataset manifest — known PCAP sources for NetMind AI validation.

Each entry provides a download URL, expected size, and ground-truth
label information.  The manifest is used by the validation runner to
optionally download datasets (via ``--download``) or to document what
datasets are expected.

Sources
-------
- **CICIDS2017**: Canadian Institute for Cybersecurity IDS 2017
  https://www.unb.ca/cic/datasets/ids-2017.html
  Contains modern attacks (DDoS, brute force, infiltration, botnet).

- **CTU-13**: Czech Technical University — 13 botnet scenarios
  https://www.stratosphereips.org/datasets-ctu13
  Botnet C2 + normal traffic mixed.

- **Stratosphere**: Stratosphere IPS project
  https://www.stratosphereips.org/datasets-overview
  Malware and normal traffic captures.

- **MAWILab**: MAWI Working Group Traffic Archive
  https://mawi.wide.ad.jp/mawi/
  Backbone traffic with labeled attacks.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DatasetPCAP:
    """A single known PCAP file in the manifest."""

    source: str  # e.g., "cicids2017", "ctu13"
    filename: str
    url: str | None = None
    size_bytes: int | None = None
    attack_present: bool = False
    attack_types: list[str] = field(default_factory=list)
    notes: str = ""


# ---------------------------------------------------------------------------
# Manifest registry
# ---------------------------------------------------------------------------

MANIFEST: list[DatasetPCAP] = [
    # ---- CICIDS2017 ----
    DatasetPCAP(
        source="cicids2017",
        filename="Friday-WorkingHours.pcap",
        attack_present=True,
        attack_types=["port_scan", "ddos", "brute_force"],
        notes="CICIDS2017 Friday working hours — port scan + DDoS + brute force.",
    ),
    DatasetPCAP(
        source="cicids2017",
        filename="Monday-Benign.pcap",
        attack_present=False,
        attack_types=[],
        notes="CICIDS2017 Monday — benign background traffic.",
    ),
    # ---- CTU-13 ----
    DatasetPCAP(
        source="ctu13",
        filename="ctu13-scenario-1.pcap",
        attack_present=True,
        attack_types=["botnet_c2", "port_scan", "spam"],
        notes="CTU-13 Scenario 1 — Neris botnet (IRC).",
    ),
    DatasetPCAP(
        source="ctu13",
        filename="ctu13-scenario-8.pcap",
        attack_present=True,
        attack_types=["botnet_c2"],
        notes="CTU-13 Scenario 8 — Murlo botnet.",
    ),
    # ---- Stratosphere ----
    DatasetPCAP(
        source="stratosphere",
        filename="capture-1-android-benchmark.pcap",
        attack_present=True,
        attack_types=["malware"],
        notes="Stratosphere — Android malware traffic.",
    ),
    DatasetPCAP(
        source="stratosphere",
        filename="capture-2-normal.pcap",
        attack_present=False,
        attack_types=[],
        notes="Stratosphere — normal device traffic.",
    ),
    # ---- MAWILab ----
    DatasetPCAP(
        source="mawilab",
        filename="mawi-20240101-sample.pcap",
        attack_present=True,
        attack_types=["ddos", "scan"],
        notes="MAWILab sample — labeled backbone attack traffic.",
    ),
]
