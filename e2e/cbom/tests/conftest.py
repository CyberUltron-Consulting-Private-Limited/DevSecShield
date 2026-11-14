"""Put e2e/cbom on sys.path so ``import harness`` works from any working directory."""
import sys
from pathlib import Path

CBOM = Path(__file__).resolve().parents[1]
if str(CBOM) not in sys.path:
    sys.path.insert(0, str(CBOM))
