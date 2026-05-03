from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from collector.security.cve.product_aliases import enrich_software_entry


DEFAULT_SNAPSHOT_PATH = REPO_ROOT / "collector" / "output" / "software_snapshot" / "software_snapshot_latest.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="Preview CVE candidate products from a software snapshot.")
    parser.add_argument(
        "--snapshot",
        default=str(DEFAULT_SNAPSHOT_PATH),
        help="Path to software_snapshot_latest.json.",
    )

    args = parser.parse_args()
    snapshot_path = Path(args.snapshot)

    with snapshot_path.open("r", encoding="utf-8") as file:
        snapshot = json.load(file)

    candidates = []

    for entry in snapshot.get("software", []):
        enriched = enrich_software_entry(entry)
        if enriched:
            candidates.append(enriched)

    output = {
        "source_snapshot": str(snapshot_path),
        "snapshot_generated_at": snapshot.get("generated_at"),
        "total_software": snapshot.get("software_count", 0),
        "cve_candidate_count": len(candidates),
        "candidates": candidates,
    }

    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())