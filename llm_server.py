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


@mcp.tool(title="LLM benchmarking",description="Run a LLM benchmarking for an LLM Model")
def llm_benchmarking(
    model_type: Literal["openai","custom","anthropic","google"],
    probes: str,
    llm_model: str | None = None,
    api_key: str | None = None,
    headers: dict | None = None,
    request_template: dict | None = None,
    response_json_field: str | None = None,
    model_uri: str | None = None
):
    """
    Run a LLM benchmarking for an LLM Model
    Args:
        llm_model: The model to benchmark
        model_type: The type of the model
    Returns:
        The results of the LLM benchmarking
    """
    if not llm_model or not model_type:
        raise ToolError("LLM model, model type and probes are required")
    return run_garak_scan(
        model_type=model_type,
        model_name=llm_model,
        api_key=api_key,
        headers=headers,
        request_template=request_template,
        response_json_field=response_json_field,
        probes=probes,
        model_uri=model_uri,
    )

def run_llm_server():
    try:
        mcp.run(transport="http", port=8004)
    except KeyboardInterrupt:
        Console().print("MCP server stopped",style="bold red")
    except asyncio.exceptions.CancelledError:
        Console().print("MCP server stopped",style="bold red")
    except Exception as e:
        Console().print(e,style="bold red")
        Console().print("Error starting MCP server",style="bold red")
if __name__ == "__main__":
    run_llm_server()