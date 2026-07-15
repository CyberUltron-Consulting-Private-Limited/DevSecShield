from helpers.checks.nuclei.construct_temp import construct_navigate_action
from helpers.agent.context import AuthRequirements
from helpers.checks.page_analysis import construct_login_template, construct_navigate_template
import tempfile
from langchain_core.documents import Document
from helpers.checks.nuclei.run_nuclei import run_nuclei
from rich.console import Console
console = Console()



def get_page_content(url: str,auth: AuthRequirements) -> str:
    try:
        new_login_template = construct_login_template(auth)
        new_navigate_template = construct_navigate_template(url)

        new_template = new_login_template + new_navigate_template

        temp_yaml_file = tempfile.NamedTemporaryFile(delete=False,suffix=".yaml")

        with open(temp_yaml_file.name, "w+") as f:
            f.write(new_template)
        

        result : list[Document] = run_nuclei(template_path=temp_yaml_file.name, url=url)

        page_content = ""
        for document in result:
            page_content += document.page_content
        
        console.print(f"HTML Page content length: {len(page_content)} characters",style="bold green")
        return page_content

    except Exception as e:
        console.print(f"Error in getting page content: {e}",style="bold red")
        raise Exception(f"Error in getting page content: {e}")


def get_auth_login_template(url: str,auth: AuthRequirements) -> str:
    try:
        new_login_template = construct_login_template(auth)
        new_navigate_template = construct_navigate_action(url)

        new_template = new_login_template + new_navigate_template + "\n\n<ADD_YOUR_EXPLOIT_ACTIONS_HERE>"

        return new_template
        
    except Exception as e:
        console.print(f"Error in getting auth login template: {e}",style="bold red")
        raise Exception(f"Error in getting auth login template: {e}")
