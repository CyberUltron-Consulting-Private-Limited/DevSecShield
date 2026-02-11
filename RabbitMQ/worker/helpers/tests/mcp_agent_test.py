import json
from helpers.tools.mcp_agent.main import MCPAgent
from helpers.tools.mcp_agent.context import MCPContext
from rich.console import Console
console = Console()

def main():
    http_server_url = "https://mcp.brightdata.com/mcp?token=391e10c0-0785-4c46-bfba-4df8d3933968&groups=advanced_scraping,ecommerce"
    server_mode = "httpstreamable"
    mcp_kwargs = {
        "server_url":http_server_url,
        "server_mode":server_mode
    }
    mcp_context = MCPContext.model_validate_json(json.dumps(mcp_kwargs))
    agent = MCPAgent(mcp_context=mcp_context)
    report = agent.run_agent()
    console.print(report,style="bold yellow")

if __name__ == "__main__":
    main()
