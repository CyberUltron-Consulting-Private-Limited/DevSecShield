import asyncio
from multiprocessing import Process
from fastmcp import FastMCP 
from fastmcp.exceptions import ToolError
from pydantic import Field , BaseModel
from rich.console import Console
from tools.sbom_sca_utils.sbom_runner import run_sbom_scan
mcp = FastMCP("My MCP Server")

# Define the JSON response model
class JSONResponse(BaseModel):
    json_data: str = Field(description="The final validated JSON string")
    error: bool = Field(description="Whether the JSON string is valid or not")

description_sbom_sca="""Run a SBOM + SCA scan on the repository and return the results. 
Arguments: 
    repo_url: The URL of the repository to scan
    PAT: The Personal Access Token for the repository
Returns:
    The results of the SBOM + SCA scan
"""

@mcp.tool(title="SBOM + SCA Scan",description=description_sbom_sca)
def sbom_sca_scan(repo_url: str,PAT: str):
    """
    Run a SBOM + SCA scan on the repository and return the results
    Args:
        repo_url: The URL of the repository to scan
        PAT: The Personal Access Token for the repository
    Returns:
        The results of the SBOM scan
    """
    if not repo_url or not PAT:
        raise ToolError("Repository URL and PAT are required")
    return run_sbom_scan(repo_url,PAT)


def run_sbom_sca_server():
    try:
        mcp.run(transport="http", port=8002)
    except KeyboardInterrupt:
        Console().print("MCP server stopped",style="bold red")
    except asyncio.exceptions.CancelledError:
        Console().print("MCP server stopped",style="bold red")
    except Exception as e:
        Console().print(e,style="bold red")
        Console().print("Error starting MCP server",style="bold red")
if __name__ == "__main__":
    run_sbom_sca_server()