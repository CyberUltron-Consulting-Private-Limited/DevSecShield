import re
from rich.console import Console
# from helpers.crawler.scrapy_crawl import get_child_urls
from helpers.crawler.native_crawler import crawl as get_child_urls

console = Console(markup=False)


class Crawler():

    def __init__(
        self, 
        url: str, 
        max_urls: int = 100,
        additional_urls_to_scan: list[str] | None = None,
        include_url_patterns : list[str] = [],
        exclude_url_patterns : list[str] = [],
        egress=None,
        ):

        # STEP [ 1 ] ----------------> Validate the input data --------------------------
        if not url:
            raise ValueError("URL is required")
        if max_urls is None:
            raise ValueError("Max URLs is required")

        if include_url_patterns and exclude_url_patterns and len(include_url_patterns) > 0 and len(exclude_url_patterns) > 0:
            raise ValueError("Either include or exclude url patterns are required , Both cannot be used together")
        

        # STEP [ 2 ] ----------------> Initialize the crawler --------------------------
        self.url = url
        self.max_urls = max_urls
        self.additional_urls_to_scan = additional_urls_to_scan
        self.include_url_patterns = include_url_patterns
        self.exclude_url_patterns = exclude_url_patterns
        self.final_urls_to_scan = []
        self.egress = egress  # helpers.net.egress.ScanEgress: every crawl request is pinned through it

        self.metadata = {
            "urls_included": [],
            "urls_excluded": [], 
        }



    def crawl(self):
        try:

            discovered_urls = get_child_urls(start_url=self.url, max_urls=self.max_urls, egress=self.egress)
            console.print(f"Discovered {len(discovered_urls)} URLs", style="bold yellow1")

            if self.include_url_patterns:
                discovered_urls = self.filter_based_on_include_url_patterns(discovered_urls, self.include_url_patterns)
                console.print(f"Filtered {len(discovered_urls)} URLs based on include url patterns", style="bold yellow1")
            elif self.exclude_url_patterns:
                discovered_urls = self.filter_based_on_exclude_url_patterns(discovered_urls, self.exclude_url_patterns)
                console.print(f"Filtered {len(discovered_urls)} URLs based on exclude url patterns", style="bold yellow1")
            else:
                self.metadata["urls_included"] = discovered_urls
                console.print(f"No url patterns to filter URLs", style="bold yellow1")

            if self.additional_urls_to_scan:
                self.metadata["urls_included"].extend(self.additional_urls_to_scan)
                discovered_urls.extend(self.additional_urls_to_scan)
                console.print(f"Added {len(self.additional_urls_to_scan)} additional URLs to scan", style="bold yellow1")

            # Preserve order while dropping duplicates from filters or additional URLs.
            self.final_urls_to_scan = list(dict.fromkeys(discovered_urls))
            self.metadata["urls_included"] = list(dict.fromkeys(self.metadata["urls_included"]))
            self.metadata["urls_excluded"] = list(dict.fromkeys(self.metadata["urls_excluded"]))
            return self.final_urls_to_scan
        
        except Exception as e:
            console.print(f"Error in crawl: {e}", style="bold red")
            raise e 


    def filter_based_on_include_url_patterns(self, urls: list[str], include_url_patterns: list[str]) -> list[str]:
        try: 
            filtered_urls = []
            for url in urls:
                if any(does_url_match_pattern(url, pattern) for pattern in include_url_patterns):
                    filtered_urls.append(url)
                    self.metadata["urls_included"].append(url)
                else:
                    self.metadata["urls_excluded"].append(url)
            return filtered_urls
        except Exception as e:
            console.print(f"Error in filter_based_on_include_url_patterns: {e}", style="bold red")
            raise e 

    def filter_based_on_exclude_url_patterns(self, urls: list[str], exclude_url_patterns: list[str]) -> list[str]:
        try: 
            filtered_urls = []
            for url in urls:
                if any(does_url_match_pattern(url, pattern) for pattern in exclude_url_patterns):
                    self.metadata["urls_excluded"].append(url)
                else:
                    filtered_urls.append(url)
                    self.metadata["urls_included"].append(url)
            return filtered_urls
        except Exception as e:
            console.print(f"Error in filter_based_on_exclude_url_patterns: {e}", style="bold red")
            raise e 


def does_url_match_pattern(url: str, pattern: str) -> bool:
    """
    The patterns will look like this : 

    https://demo.testfire.net/*
    or 
    https://demo.testfire.net/*/items.jsp

    build the regex so that anything can match in place of the * 
    """
    try:
        # STEP [ 1 ] ------------------------------- Build Regex string ------------------------------------
        regex = pattern.replace("*", ".*")
            
        # STEP [ 2 ] ---------------------- Search for regex in url ------------------------------------
        if re.search(regex, url):
            return True
        else:
            return False

    except Exception as e:
        raise ValueError(f"Error in does_url_match_pattern: {e}")

