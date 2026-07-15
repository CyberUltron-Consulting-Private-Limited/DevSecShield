from playwright.sync_api import Page
from rich.console import Console
from playwright.sync_api import Browser
from helpers.agent.BaseTest import BaseTest
from helpers.agent.BaseUtilities import BaseUtilities
from pydantic import BaseModel
console = Console()
from playwright.sync_api import sync_playwright, expect


def security_headers_check(url: str)->list[str]:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            context = browser.new_context()
            page = context.new_page()
            findings = test_for_security_headers_on_target_url_page(page, url)
            context.close()
            browser.close()
            return findings

def test_for_security_headers_on_target_url_page(page: Page, target_url: str):
    """
    Checks for the presence and basic configuration of key security headers
    on the user's account overview page.
    """

    try:
        findings : list[str] = []

        response = page.goto(target_url)
        headers = response.headers

        console.print(f"Security Headers Test for URL: {target_url}",style="bold yellow")
        # for name, value in headers.items():
        #     console.print(f"{name}: {value}",style="dim bright_cyan")

        # ---------------Specific Checks for Security Headers---------------

        # Content Security Policy (CSP): Helps prevent XSS attacks
        csp = headers.get('content-security-policy')
        if csp is None:
            findings.append("Content-Security-Policy header is missing!")
        else:
            findings.append(f"Content-Security-Policy header found with value : {csp} !")
        # We might want to add more specific checks on the CSP value later.

        # Strict-Transport-Security (HSTS): Forces secure HTTPS connections
        hsts = headers.get('strict-transport-security')
        if hsts is None:
            findings.append("Strict-Transport-Security header is missing!")
        else:
            findings.append(f"Strict-Transport-Security header found with value : {hsts} !")
        # We might check for 'max-age' and 'includeSubDomains'.

        # X-Frame-Options: Helps prevent clickjacking
        xfo = headers.get('x-frame-options')
        if xfo is None:
            findings.append("X-Frame-Options header is missing!")
        else:
            findings.append(f"X-Frame-Options header found with value : {xfo} !")

        # X-Content-Type-Options: Prevents MIME sniffing
        xcto = headers.get('x-content-type-options')
        if xcto is None:
            findings.append("X-Content-Type-Options header is missing!")
        else:
            findings.append(f"X-Content-Type-Options header found with value : {xcto} !")

        return findings
    
    except Exception as e:
        console.print(f"Error while testing security headers: {e}",style="bold red")
        raise e 
    

class SecurityHeadersCheck(BaseTest,BaseUtilities):

    def __init__(self, url: str , vulnerability_model: type[BaseModel]):
        
        if not url:
            raise ValueError("URL is required")
        
        if not url.startswith("http"):
            url = f"https://{url}"

        self.url = url
        self.vulnerability_model = vulnerability_model
    
    def run(self)->type[BaseModel]:
        """
        Run the security headers check
        """
        findings =  security_headers_check(self.url)

        output = self.generate_structured_response(
            prompt=f"Analyze the following findings and generate a vulnerability report: {findings}",
            system_prompt=f"You are a security expert and you are tasked with analyzing the security headers of a target URL and generating a vulnerability report.",
            output_model=self.vulnerability_model,
        )
        return output


    
