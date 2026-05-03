from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.append(str(REPO_ROOT))

from collector.security.cve.software_snapshot import create_software_snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a SAGE-CH software snapshot from endpoint reports.")
    parser.add_argument(
        "--input-dir",
        default=str(REPO_ROOT / "collector" / "input" / "incoming"),
        help="Directory containing endpoint report JSON files.",
    )
    parser.add_argument(
        "--output",
        default=str(REPO_ROOT / "collector" / "output" / "software_snapshot" / "software_snapshot_latest.json"),
    )

    args = parser.parse_args()

    result = create_software_snapshot(
        input_dir=Path(args.input_dir),
        output_path=Path(args.output),
    )

    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())