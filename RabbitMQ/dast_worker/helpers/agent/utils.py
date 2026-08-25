import tempfile

from langchain_core.documents import Document
from rich.console import Console

from helpers.agent.context import AuthRequirements
from helpers.agent.page_surface import documents_to_text
from helpers.checks.nuclei.construct_temp import (
    construct_login_template,
    construct_navigate_action,
    construct_navigate_template,
)
from helpers.checks.nuclei.run_nuclei import run_nuclei

console = Console(markup=False)


def fetch_authenticated_page(
    url: str,
    auth: AuthRequirements,
    timeout_seconds: int = 90,
) -> tuple[str, list[Document]]:
    new_login_template = construct_login_template(auth)
    new_navigate_template = construct_navigate_template(url)
    new_template = new_login_template + new_navigate_template
    temp_yaml_file = tempfile.NamedTemporaryFile(delete=False, suffix=".yaml")
    with open(temp_yaml_file.name, "w+") as handle:
        handle.write(new_template)
    documents = run_nuclei(
        template_path=temp_yaml_file.name,
        url=url,
        timeout_seconds=timeout_seconds,
    )
    page_content = documents_to_text(documents)
    console.print(f"HTML Page content length: {len(page_content)} characters", style="bold green")
    return page_content, documents


def get_page_content(url: str, auth: AuthRequirements, timeout_seconds: int = 90) -> str:
    try:
        page_content, _documents = fetch_authenticated_page(
            url, auth, timeout_seconds=timeout_seconds
        )
        return page_content
    except Exception as e:
        console.print(f"Error in getting page content: {e}", style="bold red")
        raise Exception(f"Error in getting page content: {e}")


def get_auth_login_template(url: str, auth: AuthRequirements) -> str:
    try:
        new_login_template = construct_login_template(auth)
        new_navigate_template = construct_navigate_action(url)
        return new_login_template + new_navigate_template + "\n\n<ADD_YOUR_EXPLOIT_ACTIONS_HERE>"
    except Exception as e:
        console.print(f"Error in getting auth login template: {e}", style="bold red")
        raise Exception(f"Error in getting auth login template: {e}")
