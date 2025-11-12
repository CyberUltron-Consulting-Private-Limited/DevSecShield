import asyncio
from fastmcp import Client
from rich.console import Console

client = Client("http://localhost:8000/mcp")

async def call_tool(tool_name: str, **kwargs):
    async with client:
        result = await client.list_tools()
        print(result)

async def main():
    #common
    
    PAT="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"
    OPENAI_API_KEY="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"

    # #sast
    # sast_repo="https://github.com/CyberUltron-Nikhil/RiskPilot"
    # app_lang="javascript"
    # result = await call_tool("sast_scan", repo_url=sast_repo, PAT=PAT, app_lang=app_lang)
    # Console().print("SAST scan completed",style="bold green")

    # #discovery
    # discovery_repo="https://github.com/yacwagh/double-trust"
    # result = await call_tool("discovery_scan", repo_url=discovery_repo, PAT=PAT)
    # Console().print("Discovery scan completed",style="bold green")

    #iac
    iac_repo="https://github.com/CyberUltron-Nikhil/DevSecShield"
    result = await call_tool("iac_scan", repo_url=iac_repo, PAT=PAT)
    Console().print("IAC scan completed",style="bold green")

    # #sbom sca
    # sbom_repo="https://github.com/CyberUltron-Nikhil/Riskpilot"
    # result = await call_tool("sbom_sca_scan", repo_url=sbom_repo, PAT=PAT)
    # Console().print("SBOM scan completed",style="bold green")


if __name__ == "__main__":
    asyncio.run(call_tool(tool_name="list_tools"))