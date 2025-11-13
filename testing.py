import asyncio
from fastmcp import Client
from rich.console import Console

client = Client("http://localhost:8000/mcp")

async def call_tool(tool_name: str, **kwargs):
    async with client:
        result = await client.call_tool(tool_name, kwargs)
        return result

async def main():
    #common
    
    PAT="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"
    OPENAI_API_KEY="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"


    # mcp scanning  ✅ tested 
#     mcp_input="""
#     {
#     "mcpServers": {
#       "playwright": {
#         "command": "npx",
#         "args": [
#           "@playwright/mcp@latest"
#         ]
#       } ,
#       "howtocook-mcp": {
#       "command": "npx",
#       "args": [
#         "-y",
#         "howtocook-mp"
#       ]
#     }
#     }
#   }
#     """
#     result = await call_tool("mcp_scan", server_config_json=mcp_input)
#     Console().print("MCP scan completed",style="bold green")

    # gitleaks scan ✅ tested
    # gitleaks_repo="https://github.com/CyberUltron-Nikhil/RiskPilot"
    # result = await call_tool("code_and_data_leakage_scan", repo_url=gitleaks_repo, PAT=PAT)
    # Console().print("Gitleaks scan completed",style="bold green")

    # sast ✅ tested
    # sast_repo="https://github.com/CyberUltron-Nikhil/RiskPilot"
    # app_lang="javascript"
    # result = await call_tool("sast_scan", repo_url=sast_repo, PAT=PAT, app_lang=app_lang)
    # Console().print("SAST scan completed",style="bold green")

    # #discovery ✅ tested
    # discovery_repo="https://github.com/yacwagh/double-trust"
    # result = await call_tool("agent_scan", repo_url=discovery_repo, PAT=PAT)
    # Console().print("Discovery scan completed",style="bold green")

    # iac ✅ tested
    # iac_repo="https://github.com/CyberUltron-Nikhil/DevSecShield"
    # result = await call_tool("iac_scan", repo_url=iac_repo, PAT=PAT)
    # Console().print("IAC scan completed",style="bold green")

    # sbom sca ✅ tested
    # sbom_repo="https://github.com/CyberUltron-Nikhil/Riskpilot"
    # result = await call_tool("sbom_sca_scan", repo_url=sbom_repo, PAT=PAT)
    # Console().print("SBOM scan completed",style="bold green")

    #llm benchmarking ✅ tested 
    # result = await call_tool("llm_benchmarking", model_type="openai", llm_model="gpt-4o", probes="malwaregen.TopLevel",api_key="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")
    # Console().print("LLM benchmarking completed",style="bold green")
    # Console().print(result,style="bold green")


    # #llm benchmarking ( custom model ) ✅ tested
    # result = await call_tool(
    #     "llm_benchmarking", 
    #     model_type="custom",
    #     llm_model="gpt-4o",
    #     headers={
    #             "Authorization": "Bearer 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",
    #             "Content-Type": "application/json"
    #             },
    #     request_template={
    #         "model": "gpt-4o",
    #         "input": "$INPUT"
    #       },
    #     response_json_field="$.output[0].content[0].text",
    #     probes="malwaregen.TopLevel",
    #     model_uri="https://api.openai.com/v1/responses",
    # )
    # Console().print("LLM benchmarking ( custom model ) completed",style="bold green")
    # Console().print(result,style="bold green")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        Console().print(f"Error : {e}",style="bold red")