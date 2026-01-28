from helpers.tools.iac_agent.main import IACAgent
from helpers.context.scan_context import ZipContext
from helpers.tools.iac_agent.context import IACTypeContext
from rich.console import Console
from helpers.parsers.base_vuln import parse_vuln
import json
console = Console()

if __name__ == "__main__":

    zip_context = ZipContext(
            bucket_name="devsecshield-storage",
            object_name="IAC_testing-main.zip"
            # object_name="RiskPilot-main (1).zip"
            # object_name="DevSecShield-main.zip"
        )
    iac_agent = IACAgent(
        zip_context=zip_context,
        iac_contexts=[
            # IACTypeContext(
            #     mode="terraform",
            # ) , 
            # IACTypeContext(
            #     mode="k8s",
            #     include_path_arrays=[["kubernetes"]]
            # ) ,
            IACTypeContext(
                mode="pulumi",
                include_path_arrays=[["pulumi"]]
            ) ,
            # IACTypeContext(
            #     mode="helm",
            #     include_path_arrays=[["helm"]]
            # ) ,
        ]
    )
    output = iac_agent.run_agent()

    console.print(f"Output : {output}",style="dim yellow")

    parsed_output = iac_agent.to_dict_list(output)

    console.print(f"Vulnerabilities : {parsed_output}",style="dim yellow")

    with open("iac_agent_test_output.json", "w") as f:
        json.dump(parsed_output, f, indent=2)