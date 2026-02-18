from checks.security_headers import test_for_security_headers_on_target_url_page
from rich.console import Console
console = Console()


if __name__ == '__main__':
    from playwright.sync_api import sync_playwright, expect

    base_url = "https://threatshield.zeroshield.ai" # Replace with your application's URL

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context()
        page = context.new_page()
        findings = test_for_security_headers_on_target_url_page(page, base_url)
        for finding in findings:
            console.print(f"{finding}",style="bold red")
        context.close()
        browser.close()