"""Credit formula for automatic DAST (no live crawl)."""


def credits_for_auto_dast(max_urls: int | None) -> float:
    n = max_urls if isinstance(max_urls, int) and max_urls >= 1 else 100
    return round(n * 0.08, 2)
