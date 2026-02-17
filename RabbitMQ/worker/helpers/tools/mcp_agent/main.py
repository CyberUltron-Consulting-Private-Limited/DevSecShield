from helpers.tools.mcp_agent.mcp_client import MCPClient
from helpers.context.base_agent import BaseAgent
from helpers.tools.mcp_agent.context import MCPContext, MCPReconContext, MCPTool, MCPResource , MCPPrompt
from langchain_text_splitters import RecursiveCharacterTextSplitter
from helpers.context.schema import MCPResourceResponse, MCPVulnerability
import asyncio
from rich.console import Console
from helpers.context.progress_writer import StateUpdateWriter
from pydantic import BaseModel, Field
console = Console()

class FinalMCPVulnerabilities(BaseModel):
    vulnerabilities: list[MCPVulnerability] = Field(..., description="A list of MCP Vulnerabilities , where each vulnerability is related to a particular tool, you can leave the array empty if no vulnerabilities are found")


class MCPAgent(BaseAgent):
    """
    Generate a Report using MCP Client , 
    cycle through each tool and generate vulnerabilities for each tool
    """
    def __init__(
        self,
        mcp_context: MCPContext,
        state_update_writer: StateUpdateWriter | None = None,
        ):
        self.mcp_context : MCPContext = mcp_context
        self.state_update_writer : StateUpdateWriter | None = state_update_writer

        self.recon_context : MCPReconContext = None
        self.vulnerabilities : list[MCPVulnerability] = None

        self.output : dict = {}
    

    def analyze_tool(self, tool: MCPTool):
        """
        Analyze the tool and generate vulnerabilities for the tool
        """
        try:
            prompt = f"""
            You are a security expert tasked with analyzing the tool {tool.name} and generating vulnerabilities for the tool.
            The tool description is {tool.description}.
            The tool input schema is {tool.input_schema}.
            The tool output schema is {tool.output_schema}.
            """
            response : type[FinalMCPVulnerabilities] = self.generate_structured_response(
                prompt=prompt, 
                system_prompt="You are a security expert tasked with analyzing the tool and generating vulnerabilities for the tool.",
                output_model=FinalMCPVulnerabilities,
                )
            
            resource_response : type[MCPResourceResponse] = self.generate_structured_response(
                prompt=prompt, 
                system_prompt="You are a security expert tasked with analyzing the tool and finding out some details about the tool like the category of the tool, the risk level of the tool, etc.",
                output_model=MCPResourceResponse,
                )
            return response.vulnerabilities, resource_response
        except Exception as e:
            console.print(f"Error in analyzing tool: {e}",style="bold red")
            raise e
    
    def analyze_resource(self, resource: MCPResource):
        """
        Analyze the resource and generate vulnerabilities for the resource
        """
        try:
            prompt = f"""
            You are a security expert tasked with analyzing the resource {resource.name} and generating vulnerabilities for the resource.
            The resource description is {resource.description}.
            The resource input schema is {resource.size}.
            The resource type is {resource.uri}.
            """
            response : type[FinalMCPVulnerabilities] = self.generate_structured_response(
                prompt=prompt, 
                system_prompt="You are a security expert tasked with analyzing the resource and generating vulnerabilities for the resource.",
                output_model=FinalMCPVulnerabilities,
                )
            
            resource_response : type[MCPResourceResponse] = self.generate_structured_response(
                prompt=prompt, 
                system_prompt="You are a security expert tasked with analyzing the resource and finding out some details about the resource like the category of the resource, the risk level of the resource, etc.",
                output_model=MCPResourceResponse,
                )
            return response.vulnerabilities, resource_response
        except Exception as e:
            console.print(f"Error in analyzing tool: {e}",style="bold red")
            raise e
    
    def analyze_prompt(self, prompt: MCPPrompt):
        """
        Analyze the prompt and generate vulnerabilities for the prompt
        """
        try:
            prompt = f"""
            You are a security expert tasked with analyzing the prompt {prompt.name} and generating vulnerabilities for the prompt.
            The prompt description is {prompt.description}.
            The prompt input schema is {prompt.arguments}.
            """
            response : type[FinalMCPVulnerabilities] = self.generate_structured_response(
                prompt=prompt, 
                system_prompt="You are a security expert tasked with analyzing the prompt and generating vulnerabilities for the prompt.",
                output_model=FinalMCPVulnerabilities,
                )
            
            resource_response : type[MCPResourceResponse] = self.generate_structured_response(
                prompt=prompt, 
                system_prompt="You are a security expert tasked with analyzing the prompt and finding out some details about the prompt like the category of the prompt, the risk level of the prompt, etc.",
                output_model=MCPResourceResponse,
                )
            return response.vulnerabilities, resource_response
        except Exception as e:
            console.print(f"Error in analyzing prompt: {e}",style="bold red")
            raise e

    
    def analyze_mcp(
        self, 
        tools: list[MCPTool] | None = None, 
        prompts: list[MCPPrompt] | None = None, 
        resources: list[MCPResource] | None = None):
        """
        Analyze the list of tools and generate vulnerabilities for each tool
        """
        try:
            tools_findings : list[dict] = []
            prompts_findings : list[dict] = []
            resources_findings : list[dict] = []

            # ------------tools analysis ------------
            if tools:
                for tool in tools:
                    vulnerabilities, resource_response = self.analyze_tool(tool)
                    parsed_vulnerabilities = self.to_dict_list(vulnerabilities)
                    tools_findings.append({
                        "tool_name": tool.name,
                        "tool_description": tool.description,
                        "tool_input_schema": tool.input_schema,
                        "tool_output_schema": tool.output_schema,
                        "tool_risk_level": resource_response.resource_risk_level,
                        "tool_category": resource_response.resource_category,
                        "vulnerabilities": parsed_vulnerabilities
                    })
            
            # ------------prompts analysis ------------
            if prompts:
                for prompt in prompts:
                    vulnerabilities, resource_response = self.analyze_prompt(prompt)
                    parsed_vulnerabilities = self.to_dict_list(vulnerabilities)
                    prompts_findings.append({
                        "prompt_name": prompt.name,
                        "prompt_description": prompt.description,
                        "prompt_input_schema": prompt.arguments,
                        "prompt_risk_level": resource_response.resource_risk_level,
                        "prompt_category": resource_response.resource_category,
                        "vulnerabilities": parsed_vulnerabilities
                    })
            
            # ------------resources analysis ------------
            if resources:
                for resource in resources:
                    vulnerabilities, resource_response = self.analyze_resource(resource)
                    parsed_vulnerabilities = self.to_dict_list(vulnerabilities)
                    resources_findings.append({
                        "resource_name": resource.name,
                        "resource_description": resource.description,
                        "resource_size": resource.size,
                        "resource_uri": resource.uri,
                        "resource_risk_level": resource_response.resource_risk_level,
                        "resource_category": resource_response.resource_category,
                        "vulnerabilities": parsed_vulnerabilities
                    })
            return (tools_findings, prompts_findings, resources_findings)

        except Exception as e:
            console.print(f"Error in analyzing MCP: {e}",style="bold red")
            raise e
    
    

    def analyze_recon_context(self):
        """
        Analyze the recon context and generate vulnerabilities for the recon context
        """
        try:
            if not self.recon_context:
                console.print(f"Recon context not found",style="bold red")
                raise Exception("Recon context not found")
            
            
            tools_findings, prompts_findings, resources_findings = self.analyze_mcp(
                tools=self.recon_context.tools,
                prompts=self.recon_context.prompts,
                resources=self.recon_context.resources
            )
            self.output["tools"] = tools_findings # SET tools findings in output ⭐
            self.output["prompts"] = prompts_findings # SET prompts findings in output ⭐
            self.output["resources"] = resources_findings # SET resources findings in output ⭐

            return self.output

        except Exception as e:
            console.print(f"Error in analyzing recon context: {e}",style="bold red")
            raise e


    def run_recon(self):
        """
        Assemble the MCP recon context and return the recon context
        set the recon context in self.recon_context ⭐
        """
        try:
            mcp_client = MCPClient(
                server_url=self.mcp_context.server_url,
                server_mode=self.mcp_context.server_mode,
                headers=self.mcp_context.headers,
            )
            recon_context = asyncio.run(mcp_client.connect_and_get_recon_context())
            self.recon_context = recon_context # SET recon context in self.recon_context ⭐
            return self.recon_context
        except Exception as e:
            console.print(f"Error in running recon: {e}",style="bold red")
            raise e

    
    def run_agent(self):
        """
        Run the agent

        Note : each tool / prompt / resource is approximately 0.004 $ ( ~ 0.005 Credits )
        """
        
        try:
            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(10)
            self.run_recon()
            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(50)
            self.analyze_recon_context()
            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(100)
            return self.output
        except Exception as e:
            console.print(f"Error in running agent: {e}",style="bold red")
            raise e
    

    def estimate_credits_required(self)->int:
        """
        Estimate the credits required for the MCP scan
        """
        try:
            # run recon
            self.run_recon() # sets the recon context in self.recon_context ⭐

            if not self.recon_context:
                raise Exception("Recon context not found")


            credits_from_tools = 0
            if self.recon_context.tools:
                number_of_tools = len(self.recon_context.tools)
                credits_from_tools = number_of_tools * 0.005

            
            credits_from_prompts = 0
            if self.recon_context.prompts:
                number_of_prompts = len(self.recon_context.prompts)
                credits_from_prompts = number_of_prompts * 0.005
            

            credits_from_resources = 0
            if self.recon_context.resources:
                number_of_resources = len(self.recon_context.resources)
                credits_from_resources = number_of_resources * 0.005
            
            total_credits = credits_from_tools + credits_from_prompts + credits_from_resources
            return total_credits

        except Exception as e:
            console.print(f"Error in estimating credits required: {e}",style="bold red")
            raise e
    
