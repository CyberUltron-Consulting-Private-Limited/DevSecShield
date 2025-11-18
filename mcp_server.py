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

description_mcp="""Run a MCP scan on the repository and return the results. 
Arguments: 
    server_config_json: The configuration file of the server
Returns:
    The results of the MCP scan
"""


@mcp.tool(title="MCP scan",description=description_mcp)
def mcp_scan(server_config_json:str):
    """
    Run a MCP scan on the repository and return the results
    Args:
        server_config: The configuration file of the server
    Returns:
        The results of the MCP scan
    """
    if not server_config_json:
        raise ToolError("Server configuration JSON is required")
    try:
        # add an LLM call to return valid json data from the server_config_json string 
        llm_response = generate_structured_response(
            prompt=f"Validate the following JSON string , check if it is valid JSON , and return a valid JSON string.  Json string to validate : {server_config_json}",
            model="gpt-4o",
            output_model=JSONResponse,
            system_prompt="You are a JSON validator. You will be given a JSON string and you need to validate it and return a valid JSON string. If the JSON string is not valid, you need to set the 'error' field to True",
        )
        if llm_response.error:
            raise ToolError(f"Error : {llm_response.error}")
        Console().print(f"LLM Validated the JSON string , data :{llm_response.json_data}🟩",style="bold green")
        result =  run_mcp_scan(llm_response.json_data)
        return result
    except ToolError as e:
        Console().print(f"Error : {e}",style="bold red")
        raise e 
    except Exception as e:
        Console().print(f"Error : {e}",style="bold red")
        raise e


def run_mcp_server():
    try:
        mcp.run(transport="http", port=8003)
    except KeyboardInterrupt:
        Console().print("MCP server stopped",style="bold red")
    except asyncio.exceptions.CancelledError:
        Console().print("MCP server stopped",style="bold red")
    except Exception as e:
        Console().print(e,style="bold red")
        Console().print("Error starting MCP server",style="bold red")
if __name__ == "__main__":
    run_mcp_server()