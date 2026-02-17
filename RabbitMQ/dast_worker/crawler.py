# crawl_urls.py
import scrapy
from urllib.parse import urlparse


class CrawlUrlsSpider(scrapy.Spider):
    name = "crawl_urls"

    def __init__(self, start_url=None, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if not start_url:
            raise ValueError("Pass start_url")

        self.start_urls = [start_url]
        self.allowed_netloc = urlparse(start_url).netloc
        self.visited = set()

    def parse(self, response):
        if response.url in self.visited:
            return

        self.visited.add(response.url)

        # output the discovered URL
        yield {"url": response.url}

        for href in response.css("a::attr(href)").getall():
            url = response.urljoin(href)
            parsed = urlparse(url)

            if parsed.scheme in ("http", "https") and parsed.netloc == self.allowed_netloc:
                yield scrapy.Request(url, callback=self.parse, dont_filter=True)
