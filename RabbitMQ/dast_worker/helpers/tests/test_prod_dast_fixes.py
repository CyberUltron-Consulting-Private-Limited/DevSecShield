from rich.console import Console
from rich.markup import MarkupError, render

from helpers.crawler.crawler import Crawler


def test_rich_markup_false_allows_nuclei_regex_text():
    console = Console(markup=False, record=True)
    payload = "Error: closing tag '[/SQL syntax/i, /ORA-/i]' at position 33"
    console.print(payload, style="bold red")
    assert "[/SQL syntax/i" in console.export_text()


def test_rich_markup_true_raises_on_nuclei_regex_text():
    raised = False
    try:
        render("Error '[/SQL syntax/i]'")
    except MarkupError:
        raised = True
    assert raised is True


def test_exclude_filter_does_not_duplicate_kept_urls():
    crawler = Crawler(url="https://example.com/", max_urls=10)
    urls = [
        "https://aimeshfirewall.zeroshield.ai/",
        "https://aimeshfirewall.zeroshield.ai/assets/index.js",
        "https://aimeshfirewall.zeroshield.ai/login",
    ]
    patterns = ["*.js", "*.css", "*.svg", "*.png", "*.jpg", "*.ico", "*.woff", "*.woff2", "*.map"]
    kept = crawler.filter_based_on_exclude_url_patterns(urls, patterns)
    assert kept.count("https://aimeshfirewall.zeroshield.ai/") == 1
    assert kept.count("https://aimeshfirewall.zeroshield.ai/login") == 1
    assert "https://aimeshfirewall.zeroshield.ai/assets/index.js" not in kept


def test_include_filter_keeps_each_matching_url_once():
    crawler = Crawler(url="https://example.com/", max_urls=10)
    urls = [
        "https://example.com/api/health/",
        "https://example.com/login",
        "https://example.com/docs",
    ]
    kept = crawler.filter_based_on_include_url_patterns(urls, ["*/api/*"])
    assert kept == ["https://example.com/api/health/"]
