from playwright.sync_api import Page
from rich.console import Console
from playwright.sync_api import Browser
console = Console()


findings : list[dict] = []

def test_security_headers_on_account_page(page: Page, base_url: str):
    """
    Checks for the presence and basic configuration of key security headers
    on the user's account overview page.
    """
    
    # page.goto(f"{base_url}/login")
    # page.fill('#username', 'testuser')
    # page.fill('#password', 'password123')
    # page.click('#login-button')
    # expect(page).to_have_url(f"{base_url}/account/overview")

    # response = page.goto(f"{base_url}/account/overview")
    response = page.goto(f"{base_url}/login")
    headers = response.headers

    console.print("Security Headers on Account Overview Page:",style="bold yellow")
    for name, value in headers.items():
        console.print(f"{name}: {value}",style="bold bright_cyan")

    # Now, let's specifically check for some important ones:

    # Content Security Policy (CSP): Helps prevent XSS attacks
    csp = headers.get('content-security-policy')
    if csp is None:
        findings.append("Content-Security-Policy header is missing!")
    else:
        console.print(f"Content-Security-Policy: {csp}",style="bold yellow")
    # We might want to add more specific checks on the CSP value later.

    # Strict-Transport-Security (HSTS): Forces secure HTTPS connections
    hsts = headers.get('strict-transport-security')
    if hsts is None:
        findings.append("Strict-Transport-Security header is missing!")
    else:
        console.print(f"Strict-Transport-Security: {hsts}",style="bold yellow")
    # We might check for 'max-age' and 'includeSubDomains'.

    # X-Frame-Options: Helps prevent clickjacking
    xfo = headers.get('x-frame-options')
    if xfo is None:
        findings.append("X-Frame-Options header is missing!")
    else:
        console.print(f"X-Frame-Options: {xfo}",style="bold yellow")

    # X-Content-Type-Options: Prevents MIME sniffing
    xcto = headers.get('x-content-type-options')
    if xcto is None:
        findings.append("X-Content-Type-Options header is missing!")
    else:
        console.print(f"X-Content-Type-Options: {xcto}",style="bold yellow")

    console.print("Security header checks completed.",style="bold green")
    

# Example usage (replace with your actual base URL and potentially adjust selectors)
def run_header_check_test(browser:Browser, base_url):
    context = browser.new_context()
    page = context.new_page()
    test_security_headers_on_account_page(page, base_url)
    context.close()

if __name__ == '__main__':
    from playwright.sync_api import sync_playwright, expect

    base_url = "https://threatshield.zeroshield.ai" # Replace with your application's URL

    with sync_playwright() as p:
        browser = p.chromium.launch()
        run_header_check_test(browser, base_url)
        browser.close()
    

    for finding in findings:
        console.print(f"{finding}",style="bold red")