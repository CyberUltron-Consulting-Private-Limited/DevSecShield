from helpers.tools.sca_sbom_agent.main import SCASBOMAgent
from rich.console import Console
from helpers.context.scan_context import FileContext , ZipContext
import json
console = Console()

if __name__ == "__main__":

    zip_context = ZipContext(
            bucket_name="devsecshield-storage",
            object_name="RiskPilot-main (1).zip" # size : Total size: 0.0002691037952899933 GB ( 0.2755622863769531 MB ) ( 288948 bytes ) ( 36 files ) , cost :     
            # object_name="DevSecShield-main.zip" # size : Total size: 0.000959618017077446 GB ( 0.9826488494873047 MB ) ( 1030382 bytes ) ( 153 files ) , cost :
        )

    file_context = FileContext( 
        bucket_name="devsecshield-storage",
        object_name="test_cDX_sbom.json"
    )
    sbom_sca_agent = SCASBOMAgent(
        zip_context=zip_context,
        # sbom_json_file_context=file_context,
    )
    output = sbom_sca_agent.run_agent()

    console.print(f"Output : {output}",style="dim yellow")

    parsed_output = sbom_sca_agent.to_dict_list(output)
    
    console.print(f"Parsed output : {parsed_output}",style="dim yellow")

    with open("sbom_sca_agent_test_output.json", "w") as f:
        json.dump(parsed_output, f, indent=2)