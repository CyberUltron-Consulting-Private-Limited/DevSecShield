from helpers.checks.security_headers import SecurityHeadersCheck
from helpers.schema import FinalVulnResponse
from pydantic import BaseModel, Field
from rich.console import Console
console = Console()


if __name__ == "__main__":

    url = "https://demo.testfire.net"
    security_headers_check = SecurityHeadersCheck(url=url, vulnerability_model=FinalVulnResponse)
    output : type[FinalVulnResponse] = security_headers_check.run()

    vulns = output.vulnerabilities

    console.print(vulns)