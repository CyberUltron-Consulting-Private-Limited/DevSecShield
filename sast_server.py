import asyncio
from multiprocessing import Process
from fastmcp import FastMCP 
from fastmcp.exceptions import ToolError
from pydantic import Field , BaseModel
from rich.console import Console
from tools.sast_utils.sast_runner import run_sast_scan
mcp = FastMCP("My MCP Server")

# Define the JSON response model
class JSONResponse(BaseModel):
    json_data: str = Field(description="The final validated JSON string")
    error: bool = Field(description="Whether the JSON string is valid or not")


description_sast="""Run a SAST scan on the repository and return the results. 
Arguments: 
    repo_url: The URL of the repository to scan
    PAT: The Personal Access Token for the repository
    app_lang: The language of the application ( if not provided, use "python" as default)
Returns:
    The results of the SAST scan
"""
@mcp.tool(title="SAST Scan",description=description_sast)
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
    if not repo_url or not PAT:
        raise ToolError("Repository URL and PAT are required")
    return run_sast_scan(repo_url,PAT,app_lang)

def run_sast_server():
    try:
        mcp.run(transport="http", port=8001)
        
    except KeyboardInterrupt:
        Console().print("MCP server stopped",style="bold red")

    except asyncio.exceptions.CancelledError:
        Console().print("MCP server stopped",style="bold red")

    except Exception as e:
        Console().print(e,style="bold red")
        Console().print("Error starting MCP server",style="bold red")

if __name__ == "__main__":
    run_sast_server()