from urllib.error import URLError
from urllib.request import Request

from rich.console import Console
from helpers.agent.BaseTest import BaseTest
from helpers.agent.BaseUtilities import BaseUtilities
from pydantic import BaseModel
from helpers.net.egress import EgressRefused, ScanEgress

console = Console(markup=False)

_REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; DevSecShield-DAST/1.0)",
    "Accept": "*/*",
}


def findings_from_headers(headers: dict) -> list[str]:
    normalized = {str(name).lower(): value for name, value in (headers or {}).items()}
    findings: list[str] = []

    csp = normalized.get("content-security-policy")
    if csp is None:
        findings.append("Content-Security-Policy header is missing!")
    else:
        findings.append(f"Content-Security-Policy header found with value : {csp} !")

    hsts = normalized.get("strict-transport-security")
    if hsts is None:
        findings.append("Strict-Transport-Security header is missing!")
    else:
        findings.append(f"Strict-Transport-Security header found with value : {hsts} !")

    xfo = normalized.get("x-frame-options")
    if xfo is None:
        findings.append("X-Frame-Options header is missing!")
    else:
        findings.append(f"X-Frame-Options header found with value : {xfo} !")

    xcto = normalized.get("x-content-type-options")
    if xcto is None:
        findings.append("X-Content-Type-Options header is missing!")
    else:
        findings.append(f"X-Content-Type-Options header found with value : {xcto} !")

    return findings


def fetch_http_headers(url: str, timeout: int = 15, egress: ScanEgress | None = None) -> dict:
    """GET through the scan's egress (pinned to checked addresses, redirects included); never without it."""
    if egress is None:
        raise EgressRefused(f"security headers not fetched for {url}: the scan's egress guard is missing")
    request = Request(url, headers=_REQUEST_HEADERS, method="GET")
    with egress.urlopen(request, timeout=timeout) as response:
        return dict(response.headers.items())


def security_headers_check(url: str, timeout: int = 15, egress: ScanEgress | None = None) -> list[str]:
    try:
        console.print(f"Security Headers Test for URL: {url}", style="bold yellow")
        return findings_from_headers(fetch_http_headers(url, timeout=timeout, egress=egress))
    except (URLError, TimeoutError, OSError) as exc:
        console.print(f"Error while testing security headers: {exc}", style="bold red")
        raise


class SecurityHeadersCheck(BaseTest, BaseUtilities):

    def __init__(self, url: str, vulnerability_model: type[BaseModel], timeout: int = 15,
                 egress: ScanEgress | None = None):
        if not url:
            raise ValueError("URL is required")
        if not url.startswith("http"):
            url = f"https://{url}"
        self.url = url
        self.vulnerability_model = vulnerability_model
        self.timeout = timeout
        self.egress = egress

    def run(self) -> type[BaseModel]:
        findings = security_headers_check(self.url, timeout=self.timeout, egress=self.egress)
        output = self.generate_structured_response(
            prompt=f"Analyze the following findings and generate a vulnerability report: {findings}",
            system_prompt="You are a security expert and you are tasked with analyzing the security headers of a target URL and generating a vulnerability report.",
            output_model=self.vulnerability_model,
        )
        return output
