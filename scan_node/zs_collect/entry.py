"""PyInstaller entry point for the zs-collect binary (see zs_scan_node/zscollect.py)."""
from zs_scan_node.zscollect import main

if __name__ == "__main__":
    raise SystemExit(main())
