import os
import urllib.request
import yaml
import ssl
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).parent.parent
DATASETS_DIR = BASE_DIR / "datasets"

# URLs
CTU13_URL = "https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/botnet-capture-20110810-neris.pcap"
STRATOSPHERE_URL = "https://mcfp.felk.cvut.cz/publicDatasets/Android-Mischief-Dataset/AndroidMischiefDataset_v2/RAT08_cli_AndroRAT/RAT08_cli_AndroRAT.pcap"

# Bypass SSL verification
ssl_context = ssl._create_unverified_context()

def download_file(url, dest):
    print(f"Downloading {url} to {dest}...")
    if dest.exists():
        print(f"File {dest} already exists, skipping.")
        return
    
    with urllib.request.urlopen(url, context=ssl_context) as response, open(dest, 'wb') as out_file:
        out_file.write(response.read())
    print(f"Downloaded {dest.name}")

def write_yaml(dest, data):
    print(f"Writing label to {dest}...")
    with open(dest, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False)

def main():
    # 1. CTU-13
    ctu13_dir = DATASETS_DIR / "ctu13"
    ctu13_dir.mkdir(parents=True, exist_ok=True)
    ctu13_pcap = ctu13_dir / "ctu13-scenario-1.pcap"
    download_file(CTU13_URL, ctu13_pcap)
    
    ctu13_label = {
        "pcap_file": "ctu13-scenario-1.pcap",
        "attack_present": True,
        "attack_types": ["botnet_c2", "port_scan"],
        "source_ips": ["147.32.84.165"],
        "notes": "CTU-13 Scenario 1 — Neris botnet IRC"
    }
    write_yaml(ctu13_dir / "ctu13-scenario-1.yaml", ctu13_label)

    # 2. Stratosphere
    strat_dir = DATASETS_DIR / "stratosphere"
    strat_dir.mkdir(parents=True, exist_ok=True)
    strat_pcap = strat_dir / "capture-1-android-benchmark.pcap"
    download_file(STRATOSPHERE_URL, strat_pcap)
    
    strat_label = {
        "pcap_file": "capture-1-android-benchmark.pcap",
        "attack_present": True,
        "attack_types": ["malware_rat", "command_and_control"],
        "source_ips": ["147.32.83.245"],
        "notes": "Stratosphere Android Mischief Dataset — cli_AndroRAT"
    }
    write_yaml(strat_dir / "capture-1-android-benchmark.yaml", strat_label)

    print("Dataset preparation complete.")

if __name__ == "__main__":
    main()
