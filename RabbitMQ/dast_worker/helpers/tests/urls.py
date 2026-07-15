from helpers.crawler.crawler import does_url_match_pattern , Cr
from rich.console import Console

console = Console()

if __name__ == "__main__":
    urls = [
        "https://demo.testfire.net/login.jsp",
        "https://demo.testfire.net/account.jsp",
        "https://demo.testfire.net/transfer.jsp",
        "https://demo.testfire.net/transfer.jsp/items.jsp",
        "https://demo.testfire.net/transfer.jsp/items.jsp/items.jsp",
        "https://demo.testfire.net/transfer.jsp/items.jsp/items.jsp/items.jsp",
        "https://demo.testfire.net/transfer.jsp/items.jsp/items.jsp/items.jsp/items.jsp?account=1234567890",
        "https://demo.testfire.net/transfer.jsp/items.jsp/items.jsp/items.jsp/items.jsp?account=1234567890&amount=1000",
        "https://demo.testfire.net/transfer.jsp/items.jsp/items.jsp/items.jsp/items.jsp?account=1234567890&amount=1000&description=Test%20Transfer",
        "https://demo.testfire.net/transfer.jsp/items.jsp/items.jsp/items.jsp/items.jsp?account=1234567890&amount=1000&description=Test%20Transfer",
        "https://demo.testfire.net/transfer.jsp?account=1234567890",
        "https://demo.testfire.net/transfer.jsp?account=1234567890&amount=1000",
        "https://demo.testfire.net/transfer.jsp?account=1234567890&amount=1000&description=Test%20Transfer",
        "https://demo.testfire.net/transfer.jsp?account=1234567890&amount=1000&description=Test%20Transfer",
    ]
    pattern = "https://demo.testfire.net/*/items.jsp"
    for url in urls:
        if does_url_match_pattern(url, pattern):
            console.print(f"URL {url} matches pattern", style="bold green")
        else:
            console.print(f"URL {url} does not match pattern", style="bold red")
        console.print("--------------------------------")