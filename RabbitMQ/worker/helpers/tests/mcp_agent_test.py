import json
from helpers.tools.mcp_agent.main import MCPAgent
from helpers.tools.mcp_agent.context import MCPContext
from rich.console import Console
console = Console()

def main():
    # http_server_url = "https://mcp.deepwiki.com/mcp" # 3 tools 
    http_server_url = "https://mcp.brightdata.com/mcp?token=391e10c0-0785-4c46-bfba-4df8d3933968&groups=advanced_scraping" # 7 tools 
    sse_server_url = "https://mcp.brightdata.com/sse?token=391e10c0-0785-4c46-bfba-4df8d3933968&groups=advanced_scraping" # 7 tools 

    server_mode = "httpstreamable"
    sse_server_mode = "sse"
    mcp_kwargs = {
        "server_url":sse_server_url,
        "server_mode":sse_server_mode
    }
    mcp_context = MCPContext.model_validate_json(json.dumps(mcp_kwargs))
    agent = MCPAgent(mcp_context=mcp_context)
    report = agent.run_agent()

    with open("mcp_agent_results_testing.json", "w") as f:
        json.dump(report, f, indent=2)

    console.print(f"MCP Agent Results saved to mcp_agent_results_testing.json",style="bold green")

if __name__ == "__main__":
    main()
