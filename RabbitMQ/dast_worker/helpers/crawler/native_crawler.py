#!/usr/bin/env python3
"""
Web Crawler - Enumerates all child URLs from a target web app.
Usage: python crawler.py <url> <max_urls>
Dependencies: Python stdlib only (no scrapy, no bs4)
"""

import sys
import re
import urllib.request
import urllib.parse
import urllib.error
from collections import deque


def normalize_url(base: str, href: str) -> str | None:
    """Resolve a href against base and normalize it."""
    try:
        full = urllib.parse.urljoin(base, href.strip())
        parsed = urllib.parse.urlparse(full)
        # Strip fragment
        clean = parsed._replace(fragment="").geturl()
        if parsed.scheme in ("http", "https"):
            return clean
    except Exception:
        pass
    return None


def extract_urls(html: str, base_url: str) -> list[str]:
    """Extract all URLs from raw HTML using regex (no bs4)."""
    # Match href and src attributes
    pattern = re.compile(
        r"""(?:href|src|action)\s*=\s*['"]([^'">\s]+)['"]""",
        re.IGNORECASE,
    )
    urls = []
    for match in pattern.finditer(html):
        url = normalize_url(base_url, match.group(1))
        if url:
            urls.append(url)
    return urls


def fetch(url: str, timeout: int = 10) -> str | None:
    """Fetch a URL and return its text content."""
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (compatible; PyCrawler/1.0)"
                )
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if "html" not in content_type.lower():
                return None
            charset = "utf-8"
            ct_match = re.search(r"charset=([\w-]+)", content_type, re.I)
            if ct_match:
                charset = ct_match.group(1)
            return resp.read().decode(charset, errors="replace")
    except Exception as e:
        print(f"  [!] Failed to fetch {url}: {e}", file=sys.stderr)
        return None


def crawl(start_url: str, max_urls: int) -> list[str]:
    """BFS crawl starting from start_url, stay on same domain."""
    parsed_start = urllib.parse.urlparse(start_url)
    base_domain = parsed_start.netloc

    visited: set[str] = set()
    queue: deque[str] = deque([start_url])
    found: list[str] = []

    print(f"\n[*] Starting crawl: {start_url}")
    print(f"[*] Max URLs      : {max_urls}")
    print(f"[*] Domain scope  : {base_domain}\n")

    while queue and len(visited) < max_urls:
        url = queue.popleft()

        if url in visited:
            continue
        visited.add(url)

        print(f"[+] ({len(visited)}/{max_urls}) Crawling: {url}")
        found.append(url)

        html = fetch(url)
        if not html:
            continue

        child_urls = extract_urls(html, url)
        for child in child_urls:
            if child in visited:
                continue
            child_parsed = urllib.parse.urlparse(child)
            # Stay within the same domain
            if child_parsed.netloc != base_domain:
                continue
            if child not in queue:
                queue.append(child)

    return found


def main():
    if len(sys.argv) != 3:
        print("Usage: python crawler.py <url> <max_urls>")
        sys.exit(1)

    start_url = sys.argv[1]
    try:
        max_urls = int(sys.argv[2])
        if max_urls < 1:
            raise ValueError
    except ValueError:
        print("[!] max_urls must be a positive integer.")
        sys.exit(1)

    # Ensure scheme is present
    if not start_url.startswith(("http://", "https://")):
        start_url = "https://" + start_url

    results = crawl(start_url, max_urls)

    print(f"\n{'='*60}")
    print(f"[*] Crawl complete. {len(results)} URL(s) found:\n")
    for i, url in enumerate(results, 1):
        print(f"  {i:>4}. {url}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()