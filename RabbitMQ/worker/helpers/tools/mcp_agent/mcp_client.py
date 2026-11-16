import asyncio
from typing import Optional
from mcp import ClientSession, ListToolsResult, ListPromptsResult, ListResourcesResult
from mcp.client.streamable_http import streamablehttp_client
from mcp.client.sse import sse_client
from rich.console import Console
from typing import Literal
from helpers.net.egress import guarded_http_client_factory
from helpers.net.guard import TargetGuard, TargetRefused
from helpers.tools.mcp_agent.context import MCPPrompt, MCPReconContext, MCPResource, MCPTool
console = Console()

MCP_FAILURE_PREFIX = "MCP connection failed: "


def _leaves(exc: BaseException):
    """The real errors inside an anyio TaskGroup's ExceptionGroup (nested groups included)."""
    if isinstance(exc, BaseExceptionGroup):
        for inner in exc.exceptions:
            yield from _leaves(inner)
    else:
        yield exc


def mcp_connection_failure(exc: BaseException) -> str:
    """Why the MCP server could not be listed, in one fixed sentence (X1, Nov 11).

    The MCP client raises an ExceptionGroup ("unhandled errors in a TaskGroup (1 sub-exception)") that Celery cannot
    serialise, so the API only saw an opaque failure and answered 500 "Credit estimation failed, please try again
    later" although the server had answered 404. The reason is one of: an HTTP status from the server, a timeout, an
    unreachable server, or an answer that is not MCP. No response body or header is included."""
    import httpx  # the MCP client's transport

    leaves = list(_leaves(exc))
    if any(isinstance(leaf, TargetRefused) for leaf in leaves):  # #53: a private or reserved address (or a redirect)
        return f"{MCP_FAILURE_PREFIX}address not allowed"
    for leaf in leaves:
        if isinstance(leaf, httpx.HTTPStatusError):
            return f"{MCP_FAILURE_PREFIX}the MCP server answered HTTP {leaf.response.status_code}"
    if any(isinstance(leaf, (httpx.TimeoutException, TimeoutError)) for leaf in leaves):
        return f"{MCP_FAILURE_PREFIX}timeout"
    if any(isinstance(leaf, (httpx.NetworkError, httpx.UnsupportedProtocol, ConnectionError, OSError)) for leaf in leaves):
        return f"{MCP_FAILURE_PREFIX}unreachable"
    return f"{MCP_FAILURE_PREFIX}not an MCP endpoint"


class MCPClient:

    def __init__(
        self, 
        server_url: str , 
        server_mode : Literal["httpstreamable","sse"],
        headers: Optional[dict] = None
    ):
        self.server_url = server_url
        self.server_mode = server_mode
        self.session: Optional[ClientSession] = None
        self.client_context = None
        self.session_context = None
        self.headers : Optional[dict] = headers
        self.guard = TargetGuard()  # #53: every connection to a checked public address (helpers/net/)

        self.tools : ListToolsResult = None
        self.prompts : ListPromptsResult = None
        self.resources : ListResourcesResult = None
        self.recon_context : MCPReconContext = MCPReconContext()
    
    async def connect_httpstreamable(self):
        # Connect to the streamable HTTP server
        self.client_context = streamablehttp_client(
            url=self.server_url,
            headers=self.headers,
            httpx_client_factory=guarded_http_client_factory(self.guard),
        )
        read_stream, write_stream, _ = await self.client_context.__aenter__()
        # Create a session using the client streams
        self.session_context = ClientSession(read_stream, write_stream) # CREATE session context ⭐
        self.session = await self.session_context.__aenter__() # CREATE session ⭐
    


    async def connect_sse(self):
        # Connect to the SSE server
        self.client_context = sse_client(
            url=self.server_url,
            headers=self.headers,
            httpx_client_factory=guarded_http_client_factory(self.guard),
        )
        read_stream, write_stream = await self.client_context.__aenter__()
        # Create a session using the client streams
        self.session_context = ClientSession(read_stream, write_stream) # CREATE session context ⭐
        self.session = await self.session_context.__aenter__() # CREATE session ⭐
        


    async def list_tools_prompts_resources(self):
        """
        List the tools, prompts, and resources available in the MCP Server
        """
        # A server that does not complete the MCP handshake is not an MCP endpoint: say so (mcp_connection_failure)
        # instead of estimating 0 credits for an empty listing.
        await self.session.initialize()
        try:

            try:
                console.print(f"Listing tools... 🔧",style="bold yellow")
                tools = await self.session.list_tools()
                self.tools : ListToolsResult = tools # SET self.tools to the tools ⭐
                console.print(f"🔧 {len(self.tools.tools)} Tools Detected !",style="bold green")
            except Exception as e:
                console.print(f"Error in listing tools: {e}",style="dim red")
                return
            
            
            try:
                console.print(f"Listing prompts... 💬",style="bold yellow")
                prompts = await self.session.list_prompts()
                self.prompts : ListPromptsResult = prompts # SET self.prompts to the prompts ⭐
                console.print(f"💬 {len(self.prompts.prompts)} Prompts Detected !",style="bold green")
            except Exception as e:
                console.print(f"Error in listing prompts: {e}",style="dim red")
                return
            
            
            try:
                console.print(f"Listing resources... 📂",style="bold yellow")
                resources = await self.session.list_resources()
                self.resources : ListResourcesResult = resources # SET self.resources to the resources ⭐
                console.print(f"📂 {len(self.resources.resources)} Resources Detected !",style="bold green")
            except Exception as e:
                console.print(f"Error in listing resources: {e}",style="dim red")
                return
            

            console.print(f"⚙️ MCP Client Connected to MCP Server: Detected {len(self.tools.tools) if self.tools else "No tools"} tools , {len(self.prompts.prompts) if self.prompts else "No prompts"} prompts , {len(self.resources.resources) if self.resources else "No resources"} resources ",style="bold green")
        
        except Exception as e:

            console.print(f"Error in listing tools, prompts, or resources: {e}",style="bold red")
            return
    
    
    async def close(self):
        try:
            console.print(f"Closing MCP Client... 🔄",style="bold yellow")
            if self.session_context:
                await self.session_context.__aexit__(None, None, None)
            if self.client_context:
                await self.client_context.__aexit__(None, None, None)
        except Exception as e:
            console.print(f"Error in closing MCP Client: {e}",style="dim red")
            return
        console.print(f"MCP Client Closed Successfully",style="bold green")
    
    def populate_recon_context(self):
        """
        Populate the recon context
        """
        # populate tools
        if self.tools and len(self.tools.tools) > 0:
            list_of_tools : list[MCPTool] = []
            for tool in self.tools.tools:
                tool_context = MCPTool(
                    name=tool.name,
                    description=tool.description,
                    input_schema=tool.inputSchema,
                    output_schema=tool.outputSchema
                )
                list_of_tools.append(tool_context)
            self.recon_context.tools = list_of_tools # SET tools ⭐
        
        # populate prompts
        if self.prompts and len(self.prompts.prompts) > 0:
            list_of_prompts : list[MCPPrompt] = []
            for prompt in self.prompts.prompts:
                prompt_context = MCPPrompt(
                    title=prompt.title,
                    description=prompt.description,
                    name=prompt.name,
                    arguments=prompt.arguments
                )
                list_of_prompts.append(prompt_context)
            self.recon_context.prompts = list_of_prompts # SET prompts ⭐
        
        # populate resources
        if self.resources and len(self.resources.resources) > 0:
            list_of_resources : list[MCPResource] = []
            for resource in self.resources.resources:
                resource_context = MCPResource(
                    title=resource.title,
                    name=resource.name,
                    description=resource.description,
                    uri=resource.uri,
                    size=resource.size
                )
                list_of_resources.append(resource_context)
            self.recon_context.resources = list_of_resources # SET resources ⭐
        
        return self.recon_context

    async def connect_and_get_recon_context(self):
        """
        Main function to connect to the MCP Server and get the recon context
        """
        self.guard.check_url(self.server_url)  # #53: refused before any connection; each later request is pinned
        try:
            if self.server_mode == "httpstreamable":
                await self.connect_httpstreamable()
            elif self.server_mode == "sse":
                await self.connect_sse()

            await self.list_tools_prompts_resources()
            if self.guard.refused:  # a refused hop the listing swallowed (it logs a failed listing and returns)
                raise TargetRefused(self.guard.refused[0])
        except (asyncio.CancelledError, Exception):
            # a refused request in a client's own task (a redirect hop) reaches this task only as a cancellation
            # (streamable HTTP) or as the session ending (SSE: the guard closed the client's connections): say why
            if self.guard.refused:
                raise TargetRefused(self.guard.refused[0]) from None
            raise

        self.populate_recon_context()
        await self.close()
        return self.recon_context


