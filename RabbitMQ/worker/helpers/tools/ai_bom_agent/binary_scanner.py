"""
Optional binary/artifact inspector for AI-BOM (stub).

There is no widely-deployed local ML-BOM artifact scanner equivalent to
cbomkit-theia, so this module is a non-fatal stub that keeps
AIBOMAgent.run_binary_scan() safe to call. It mirrors the cbom binary_scanner
interface so the agent flow is identical: the scanner reports itself as
unavailable, returns no output, and parses to an empty asset list.

When a real ML artifact scanner is integrated, implement these three functions
and the agent will pick up the additional detections without further changes.
"""

from rich.console import Console

console = Console()


def is_aibom_scanner_available() -> bool:
    """Return True if a local AI-BOM artifact scanner is installed. Stub: False."""
    return False


def run_aibom_binary_scan(directory: str) -> dict | None:
    """Run the AI-BOM artifact scanner on a directory. Stub: returns None."""
    console.print(
        "AI-BOM binary/artifact scanner is not configured, skipping binary scanning",
        style="bold yellow",
    )
    return None


def parse_ai_binary_components(output: dict | None) -> list[dict]:
    """Parse scanner output into normalized AI component dicts. Stub: empty list."""
    if not output:
        return []
    return []
