import asyncio
from fastmcp import Client

client = Client("http://localhost:8000/mcp")

async def call_tool():
    async with client:
        result = await client.call_tool("run_sast_scan", {"repo_url": "https://github.com/CyberUltron-Nikhil/RiskPilot", 
        "PAT": "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"})
        print(result)

asyncio.run(call_tool())