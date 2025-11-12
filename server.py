import asyncio
from fastmcp import FastMCP
from rich.console import Console
from tools.sbom_sca_utils.sbom_runner import run_sbom_scan
from tools.mcp_utils.mcp_runner import run_mcp_scan
from tools.sast_utils.sast_runner import run_sast_scan
from tools.discovery_utils.discovery_runner import DiscoveryService
from tools.iac_utils.iac_runner import run_iac_scan
mcp = FastMCP("My MCP Server")

@mcp.tool(title="SBOM + SCA Scan",description="Run a SBOM + SCA scan on the repository and return the results")
def sbom_sca_scan(repo_url: str,PAT: str):
    """
    Run a SBOM + SCA scan on the repository and return the results
    Args:
        repo_url: The URL of the repository to scan
        PAT: The Personal Access Token for the repository
    Returns:
        The results of the SBOM scan
    """
    return run_sbom_scan(repo_url,PAT)


@mcp.tool(title="SAST Scan",description="Run a SAST scan on the repository and return the results")
def sast_scan(repo_url: str,PAT: str,app_lang: str):
    """
    Run a SAST scan on the repository and return the results
    Args:
        repo_url: The URL of the repository to scan
        PAT: The Personal Access Token for the repository
        app_lang: The language of the application
    Returns:
        The results of the SAST scan
    """
    return run_sast_scan(repo_url,PAT,app_lang)

@mcp.tool(title="Agent Discovery Scan",description="Run an Agent discovery scan on the repository and return the results")
def agent_scan(repo_url: str,PAT: str):
    """
    Run an Agent discovery scan on the repository and return the results
    Args:
        repo_url: The URL of the repository to scan
        PAT: The Personal Access Token for the repository
    Returns:
        The results of the discovery scan
    """
    return DiscoveryService.discover_agents_from_github(github_repo_url=repo_url,PAT=PAT)

@mcp.tool(title="IAC Scan",description="Run an IAC scan on the repository and return the results")   
def iac_scan(repo_url: str,PAT: str):
    """
    Run an IAC scan on the repository and return the results
    Args:
        repo_url: The URL of the repository to scan
        PAT: The Personal Access Token for the repository
    Returns:
        The results of the IAC scan
    """
    return run_iac_scan(repo_url,PAT)





if __name__ == "__main__":
   try:
        mcp.run(transport="http", port=8000)
        

   except KeyboardInterrupt:
        Console().print("MCP server stopped",style="bold red")
   except asyncio.exceptions.CancelledError:
        Console().print("MCP server stopped",style="bold red")
   except Exception as e:
        Console().print(e,style="bold red")
        Console().print("Error starting MCP server",style="bold red")