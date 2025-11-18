from servers.sbom_sca_server import run_sbom_sca_server
from servers.sast_server import run_sast_server
from servers.mcp_server import run_mcp_server
from servers.llm_server import run_llm_server
from servers.iac_server import run_iac_server
from servers.gitleaks_server import run_gitleaks_server
from servers.discovery_server import run_discovery_server
from rich.console import Console

def main():
    try:
        console = Console()
        console.print("Starting SBOM + SCA server",style="bold green")
        p_sbom_sca = run_sbom_sca_server()
        console.print("Starting SAST server",style="bold green")
        p_sast = run_sast_server()
        # console.print("Starting MCP server",style="bold green")
        # run_mcp_server()
        # console.print("Starting LLM server",style="bold green")
        # run_llm_server()
        # console.print("Starting IAC server",style="bold green")
        # run_iac_server()
        # console.print("Starting Gitleaks server",style="bold green")
        # run_gitleaks_server()
        # console.print("Starting Discovery server",style="bold green")
        # run_discovery_server()
        p_sbom_sca.join()
        p_sast.join()
    except Exception as e:
        console.print(f"Error starting servers: {e}",style="bold red")
        console.print("Exiting...",style="bold red")
        exit(1)

if __name__ == "__main__":
    main()