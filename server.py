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

@mcp.tool(title="MCP scan",description="Run a MCP scan on the repository and return the results")
def mcp_scan(server_config_json:str):
    """
    Run a MCP scan on the repository and return the results
    Args:
        server_config: The configuration file of the server
    Returns:
        The results of the MCP scan
    """
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
    return run_gitleaks_scan(repo_url,PAT)





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