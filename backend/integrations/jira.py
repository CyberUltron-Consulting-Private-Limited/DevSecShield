from atlassian import Jira
from rich.console import Console
from requests.exceptions import HTTPError
console = Console()


def list_projects(jira_url: str, jira_token: str):
    """
    List all Jira projects visible to the authenticated user.
    """
    jira = Jira(
        url=jira_url,
        token=jira_token,
        cloud=True,
    )

    projects = jira.projects()

    if not projects:
        console.print("[yellow]No projects found for the provided credentials.[/yellow]")
        return []

    console.print("[bold green]Accessible Jira projects:[/bold green]")
    for project in projects:
        key = project.get("key") or project.get("projectKey") or "UNKNOWN"
        name = project.get("name") or "Unnamed project"
        console.print(f"- [cyan]{key}[/cyan]: {name}")

    return projects


def create_issue_in_project(
    jira_url: str,
    jira_token: str,
    project_key: str,
    issue_type: str,
    summary: str,
    description: str,
):
    """
    Create an issue in the specified Jira project.
    """
    jira = Jira(
        url=jira_url,
        token=jira_token,
        cloud=True,
    )

    fields = {
        "project": {"key": project_key},
        "issuetype": {"name": issue_type},
        "summary": summary,
        "description": description,
    }

    issue = jira.create_issue(fields=fields)

    issue_key = issue.get("key") if isinstance(issue, dict) else getattr(issue, "key", None)
    if issue_key:
        console.print(
            f"[bold green]Created issue[/bold green] "
            f"[cyan]{issue_key}[/cyan] in project [cyan]{project_key}[/cyan]."
        )
    else:
        console.print("[yellow]Issue created but response did not contain an issue key.[/yellow]")

    return issue


if __name__ == "__main__":
    try:
        list_projects(
            jira_url="https://zapisec.atlassian.net",
            jira_token="ATATT3xFfGF0uEi3aYaG43RCe5rsIG1JCpwWF1kISjQzDinypUNH_RdktE8yPdZWngR4-ZgW1_ezt5jLI58F_pCL4VfIcaSRCHGhNsFz6_1clUOa-aEehsXY3mg3IUB_ftgTwLop2hyfeSDlIwxbHXGN8qM0DsoM2nVMG3GQ8xFBGXKV3Q5milQ=77A114FB",
        )
    except HTTPError as e:
        console.print(f"Error listing projects: {e} with status code {e.response.status_code}",style="bold red")
        console.print(f"Error response: {e.response.text}",style="bold red")