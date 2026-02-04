
from rich.console import Console
from requests.exceptions import HTTPError
import requests
from requests.auth import HTTPBasicAuth
import json
console = Console()


def list_projects(jira_url: str, jira_token: str, jira_email: str = "support@zeroshield.ai"):
    """
    List all Jira projects visible to the authenticated user.
    """
    url = f"{jira_url}/rest/api/3/project/search"

    auth = HTTPBasicAuth(jira_email, jira_token)

    headers = {
    "Accept": "application/json"
    }

    response = requests.request(
    "GET",
    url,
    headers=headers,
    auth=auth
    )

    return response.json()


def create_issue_in_project(
    jira_url: str,
    jira_token: str,
    project_id: str,
    issue_type: str,
    summary: str,
    description: str,
    jira_email: str = "support@zeroshield.ai"
):
    """
    Create an issue in the specified Jira project (by project ID).
    """
    url = f"{jira_url}/rest/api/3/issue"

    auth = HTTPBasicAuth(jira_email, jira_token)

    headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
    }

    payload = json.dumps({
        "fields": {
            "project": {"id": project_id},
            "issuetype": {"name": issue_type},
            "summary": summary,
            "description": {
                "content": [
                    {
                        "content": [
                            {"text": description, "type": "text"}
                        ],
                        "type": "paragraph"
                    }
                ],
                "type": "doc",
                "version": 1
            }
        }
    })

    response = requests.request(
    "POST",
    url,
    data=payload,
    headers=headers,
    auth=auth
    )

    print(json.dumps(json.loads(response.text), sort_keys=True, indent=4, separators=(",", ": ")))


if __name__ == "__main__":
    try:
        # response = list_projects(
        #     jira_email="nikhil@cyberultron.com",
        #     jira_url="https://zapisec.atlassian.net",
        #     jira_token="ATATT3xFfGF0uEi3aYaG43RCe5rsIG1JCpwWF1kISjQzDinypUNH_RdktE8yPdZWngR4-ZgW1_ezt5jLI58F_pCL4VfIcaSRCHGhNsFz6_1clUOa-aEehsXY3mg3IUB_ftgTwLop2hyfeSDlIwxbHXGN8qM0DsoM2nVMG3GQ8xFBGXKV3Q5milQ=77A114FB",
        # )
        # console.print(response)

        response = create_issue_in_project(
            jira_email="nikhil@cyberultron.com",
            jira_url="https://zapisec.atlassian.net",
            jira_token="ATATT3xFfGF0uEi3aYaG43RCe5rsIG1JCpwWF1kISjQzDinypUNH_RdktE8yPdZWngR4-ZgW1_ezt5jLI58F_pCL4VfIcaSRCHGhNsFz6_1clUOa-aEehsXY3mg3IUB_ftgTwLop2hyfeSDlIwxbHXGN8qM0DsoM2nVMG3GQ8xFBGXKV3Q5milQ=77A114FB",
            project_id="10034",  # Use your project's numeric ID from Jira
            issue_type="Task",
            summary="Test Issue",
            description="This is a test issue created by the Jira API",
        )
        console.print(response)
    except HTTPError as e:
        console.print(f"Error listing projects: {e} with status code {e.response.status_code}",style="bold red")
        console.print(f"Error response: {e.response.text}",style="bold red")