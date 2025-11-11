from fastmcp import FastMCP
from tools.sbom_sca_utils.sbom_runner import run_sbom_scan
from tools.mcp_utils.mcp_runner import run_mcp_scan
from tools.sast_utils.sast_runner import run_sast_scan
from tools.discovery_utils.discovery_runner import run_discovery_scan
from tools.iac_utils.iac_runner import run_iac_scan
mcp = FastMCP("My MCP Server")

@mcp.tool
def run_sbom_sca_scan(repo_url: str,PAT: str):
    return run_sbom_scan(repo_url,PAT)


@mcp.tool
def run_sast_scan(repo_url: str,PAT: str):
    return run_sast_scan(repo_url,PAT)

@mcp.tool
def run_discovery_scan(repo_url: str,PAT: str):
    return run_discovery_scan(repo_url,PAT)

@mcp.tool
def run_iac_scan(repo_url: str,PAT: str):
    return run_iac_scan(repo_url,PAT)



if __name__ == "__main__":
    mcp.run(transport="http", port=8000)