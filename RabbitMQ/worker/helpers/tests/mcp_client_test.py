import asyncio
from helpers.tools.mcp_agent.mcp_client import MCPClient
from rich.console import Console
console = Console()


http_server_url = "https://mcp.brightdata.com/mcp?token=391e10c0-0785-4c46-bfba-4df8d3933968&groups=advanced_scraping,ecommerce"

# http_server_url = "https://mcp.deepwiki.com/mcp"

async def main():
    client = MCPClient(server_url=http_server_url,server_mode="httpstreamable")

    report = await client.connect_and_create_report()
    console.print(report,style="bold yellow")
    
if __name__ == "__main__":
    asyncio.run(main())