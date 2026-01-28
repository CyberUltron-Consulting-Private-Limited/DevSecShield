from playwright.sync_api import Page
from rich.console import Console
from playwright.sync_api import Browser
console = Console()




def test_for_security_headers_on_target_url_page(page: Page, target_url: str):
    """
    Checks for the presence and basic configuration of key security headers
    on the user's account overview page.
    """

    try:
        findings : list[dict] = []

        response = page.goto(target_url)
        headers = response.headers

        console.print("Security Headers on Account Overview Page:",style="bold yellow")
        for name, value in headers.items():
            console.print(f"{name}: {value}",style="dim bright_cyan")

        # ---------------Specific Checks for Security Headers---------------

        # Content Security Policy (CSP): Helps prevent XSS attacks
        csp = headers.get('content-security-policy')
        if csp is None:
            findings.append("Content-Security-Policy header is missing!")
        else:
            console.print(f"✅ Content-Security-Policy: {csp}",style="green")
        # We might want to add more specific checks on the CSP value later.

        # Strict-Transport-Security (HSTS): Forces secure HTTPS connections
        hsts = headers.get('strict-transport-security')
        if hsts is None:
            findings.append("Strict-Transport-Security header is missing!")
        else:
            console.print(f"✅ Strict-Transport-Security: {hsts}",style="green")
        # We might check for 'max-age' and 'includeSubDomains'.

        # X-Frame-Options: Helps prevent clickjacking
        xfo = headers.get('x-frame-options')
        if xfo is None:
            findings.append("X-Frame-Options header is missing!")
        else:
            console.print(f"✅ X-Frame-Options: {xfo}",style="green")

        # X-Content-Type-Options: Prevents MIME sniffing
        xcto = headers.get('x-content-type-options')
        if xcto is None:
            findings.append("X-Content-Type-Options header is missing!")
        else:
            console.print(f"✅ X-Content-Type-Options: {xcto}",style="green")

        console.print("Security header checks completed.",style="bold green")
        


        return findings
    
    except Exception as e:
        console.print(f"Error while testing:{str(e)[:100]}",style="bold red")


    
