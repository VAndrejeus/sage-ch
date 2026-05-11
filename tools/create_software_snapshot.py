from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from collector.security.cve.software_snapshot import (
    create_software_snapshot,
    create_software_snapshot_from_consolidated,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a SAGE-CH software snapshot.")
    parser.add_argument(
        "--source",
        choices=["latest-consolidated", "input-dir"],
        default="latest-consolidated",
        help="Source for software inventory. Defaults to the latest consolidated collector dataset.",
    )
    parser.add_argument(
        "--consolidated",
        default=None,
        help="Specific consolidated_dataset_batch_*.json file to use when --source latest-consolidated is selected.",
    )
    parser.add_argument(
        "--input-dir",
        default=str(REPO_ROOT / "collector" / "input" / "incoming"),
        help="Directory containing endpoint report JSON files when --source input-dir is selected.",
    )
    parser.add_argument(
        "--output",
        default=str(REPO_ROOT / "collector" / "output" / "software_snapshot" / "software_snapshot_latest.json"),
    )

    args = parser.parse_args()

    if args.source == "input-dir":
        result = create_software_snapshot(
            input_dir=Path(args.input_dir),
            output_path=Path(args.output),
        )
    else:
        result = create_software_snapshot_from_consolidated(
            consolidated_path=Path(args.consolidated) if args.consolidated else None,
            output_path=Path(args.output),
        )

    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
