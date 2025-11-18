import asyncio
import json
import tempfile
from fastmcp import FastMCP 
from fastmcp.exceptions import ToolError
from pydantic import Field , BaseModel
from rich.console import Console
from llm import generate_structured_response
from tools.sbom_sca_utils.sbom_runner import run_sbom_scan
from tools.mcp_utils.mcp_runner import run_mcp_scan
from tools.sast_utils.sast_runner import run_sast_scan
from tools.discovery_utils.discovery_runner import DiscoveryService
from tools.iac_utils.iac_runner import run_iac_scan
from tools.llm_utils.llm_runner import run_garak_scan
from typing import Literal
from tools.gitleaks_utils.gitleaks_runner import run_gitleaks_scan
mcp = FastMCP("My MCP Server")

# Define the JSON response model
class JSONResponse(BaseModel):
    json_data: str = Field(description="The final validated JSON string")
    error: bool = Field(description="Whether the JSON string is valid or not")

@mcp.tool(title="Code and Data leakage scan",description="Run a Code and Data leakage scan on the repository and return the results")
def code_and_data_leakage_scan(repo_url: str,PAT: str):
    """
    Run a Code and Data leakage scan on the repository and return the results
    Args:
        repo_url: The URL of the repository to scan
        PAT: The Personal Access Token for the repository
    Returns:
        The results of the Code and Data leakage scan
    """
    if not repo_url or not PAT:
        raise ToolError("Repository URL and PAT are required")
    return run_gitleaks_scan(repo_url,PAT)

def run_gitleaks_server():
    try:
        mcp.run(transport="http", port=8006)
    except KeyboardInterrupt:
        Console().print("MCP server stopped",style="bold red")
    except asyncio.exceptions.CancelledError:
        Console().print("MCP server stopped",style="bold red")
    except Exception as e:
        Console().print(e,style="bold red")
        Console().print("Error starting MCP server",style="bold red")



if __name__ == "__main__":
    run_gitleaks_server()