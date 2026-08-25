import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy.exceptions import CloseSpider
from urllib.parse import urljoin, urlparse
from rich.console import Console
import logging

console = Console(markup=False)

def get_child_urls(
    target_url: str,
    same_domain_only: bool = True,
    max_urls: int = None,
) -> list[str]:
    """
    Recursively crawls the target URL and returns all discovered child URLs.

    Args:
        target_url:       The URL to start crawling from.
        same_domain_only: If True, only follow URLs on the same domain as the target.
        max_urls:         Maximum number of URLs to collect (None = no limit).

    Returns:
        A list of unique child URLs.
    """

    for noisy in ("celery", "celery.worker", "celery.app", "celery.utils", "kombu", "amqp"):
        logging.getLogger(noisy).setLevel(logging.CRITICAL)

    
    found_urls = []

    class RecursiveSpider(scrapy.Spider):
        name = "recursive_spider"
        start_urls = [target_url]
        base_domain = urlparse(target_url).netloc

        def parse(self, response):
            for href in response.css("a::attr(href)").getall():
                full_url = urljoin(response.url, href)
                parsed = urlparse(full_url)

                # Only http/https
                if parsed.scheme not in ("http", "https"):
                    continue

                # Strip fragments
                full_url = parsed._replace(fragment="").geturl()

                # Domain filter
                if same_domain_only and parsed.netloc != self.base_domain:
                    continue

                # Skip already-seen URLs and the start URL itself
                if full_url in found_urls or full_url == target_url:
                    continue

                found_urls.append(full_url)
                console.print(f"Found URL: {full_url}", style="dim green")

                # Stop if we've hit the limit
                if max_urls and len(found_urls) >= max_urls:
                    raise CloseSpider("max_urls reached")

                # Follow the link recursively
                yield scrapy.Request(full_url, callback=self.parse)

    process = CrawlerProcess(settings={
        "LOG_ENABLED": False,
        "ROBOTSTXT_OBEY": True,
        "REQUEST_FINGERPRINTER_IMPLEMENTATION": "2.7",
        "CONCURRENT_REQUESTS": 16,
        "DEPTH_LIMIT": 0,  # 0 = unlimited depth
    })

    process.crawl(RecursiveSpider)
    process.start()


    process.stop()

    return found_urls


if __name__ == "__main__":
    import sys

    url      = sys.argv[1] if len(sys.argv) > 1 else "https://demo.testfire.net/login.jsp"
    max_urls = int(sys.argv[2]) if len(sys.argv) > 2 else 100

    urls = get_child_urls(url, max_urls=max_urls)
    console.print(f"Number of URLs found: {len(urls)}", style="bold green")
