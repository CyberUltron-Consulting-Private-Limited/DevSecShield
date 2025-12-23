
from pathlib import Path
from rich.console import Console


def snippet_with_numbers(fp: Path, start: int, end: int) -> str:
    try:
        lines = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
        return "\n".join(
            f"{i+1:>5}| {lines[i]}" for i in range(start - 1, min(end, len(lines)))
        )
    except Exception as exc:
        Console().print(f"Failed to read code snippet {fp}:{start}-{end} — {exc}",style="bold red")
        return ""