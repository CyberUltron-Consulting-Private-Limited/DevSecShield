from helpers.crawler.crawler import Crawler
from rich.console import Console

console = Console()

if __name__ == "__main__":
    url = "https://demo.testfire.net/login.jsp"
    include_url_patterns = [
        "https://demo.testfire.net/*.jsp",
    ]
    exclude_url_patterns = [
        "https://demo.testfire.net/*.jsp",
    ]
    additional_urls_to_scan = [
        "https://demo.testfire.net/transfer.jsp/items.jsp",
    ]
    crawler = Crawler(
        url=url, 
        # exclude_url_patterns=exclude_url_patterns, 
        # include_url_patterns=include_url_patterns,
        additional_urls_to_scan=additional_urls_to_scan,
        max_urls=3,
        )
    urls = crawler.crawl()

    console.print(f"Length of URLs to scan: {len(urls)}", style="bold yellow1")


    console.print("Included URLs --------------------------------------- ", style="bold yellow1")
    for url in crawler.metadata["urls_included"]:
        console.print(f"URL: {url}", style="bold green")
    

    console.print("Excluded URLs --------------------------------------- ", style="bold yellow1")
    for url in crawler.metadata["urls_excluded"]:
        console.print(f"URL: {url}", style="bold red")