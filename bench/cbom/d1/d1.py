"""CB-07 D1 benchmark lane entry point: `python3 bench/cbom/d1/d1.py --help` (see README.md)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # the lane package next to this file

from lane.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
