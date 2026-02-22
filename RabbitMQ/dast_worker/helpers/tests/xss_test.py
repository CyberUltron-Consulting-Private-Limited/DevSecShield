from helpers.agent.xss_agent import XSSAgent
from helpers.checks.page_analysis import construct_login_template, construct_navigate_template
import tempfile
from langchain_core.documents import Document
from helpers.checks.nuclei.run_nuclei import run_nuclei
from helpers.agent.context import AuthRequirements
from helpers.agent.utils import get_page_content , get_auth_login_template
from rich.console import Console
console = Console()

if __name__ == "__main__":

    target_url = "https://demo.testfire.net/index.jsp"

    xpath_of_username_field = "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[1]/td[2]/input"
    xpath_of_password_field = "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[2]/td[2]/input"
    username = "jsmith"
    password = "demo123"
    xpath_of_submit_button = "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[3]/td[2]/input"

    auth = AuthRequirements(
        login_url="https://demo.testfire.net/login.jsp",
        xpath_of_username_field=xpath_of_username_field,
        xpath_of_password_field=xpath_of_password_field,
        username=username,
        password=password,
        xpath_of_submit_button=xpath_of_submit_button
    )

    page_content = get_page_content(target_url,auth)

    auth_login_template = get_auth_login_template(target_url,auth)

    xss_agent = XSSAgent(target_url,page_content,auth_login_template)
    vulnerabilities = xss_agent.run_xss_agent_graph()

    console.print(f"Number of vulnerabilities found: {len(vulnerabilities)}",style="bold green")
    
    for vulnerability in vulnerabilities:
        console.print(f"Vulnerability Title: {vulnerability.title}",style="bold green")
        console.print(f"Vulnerability Description: {vulnerability.description}",style="dim green")
        console.print(f"Vulnerability Impact: {vulnerability.impact}",style="dim green")
        console.print(f"Vulnerability OWASP Top 10: {vulnerability.owasp_top_10}",style="dim green")
        console.print(f"Vulnerability Compliance Controls: {vulnerability.compliance_controls}",style="dim green")
        console.print(f"Vulnerability Suggested Fix: {vulnerability.suggested_fix}",style="dim green")
        console.print(f"Vulnerability Category: {vulnerability.category}",style="dim green")
        console.print(f"Vulnerability Confidence: {vulnerability.confidence}",style="dim green")
        console.print("======"*10,style="dim cyan")