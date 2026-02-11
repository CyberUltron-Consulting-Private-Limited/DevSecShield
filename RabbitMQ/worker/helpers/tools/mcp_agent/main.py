from helpers.tools.mcp_agent.mcp_client import MCPClient
from helpers.context.base_agent import BaseAgent
from helpers.tools.mcp_agent.context import MCPContext, MCPReconContext, MCPTool, MCPResource , MCPPrompt
from langchain_text_splitters import RecursiveCharacterTextSplitter
from helpers.tools.mcp_agent.summary_manager import FinalMCPVulnerabilities, MCPSummaryManager
from helpers.context.schema import MCPVulnerability
import asyncio
from rich.console import Console
console = Console()



class MCPAgent(BaseAgent):
    """
    Generate a Report using MCP Client , 
    cycle through each tool and generate vulnerabilities for each tool
    """
    def __init__(
        self,
        mcp_context: MCPContext
        ):
        self.mcp_context = mcp_context

        self.recon_context : MCPReconContext = None
        self.vulnerabilities : list[MCPVulnerability] = None

        self.output : list[dict] | None = None
    

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
            return response.vulnerabilities
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
            return response.vulnerabilities
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
            return response.vulnerabilities
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
                    vulnerabilities = self.analyze_tool(tool)
                    parsed_vulnerabilities = self.to_dict_list(vulnerabilities)
                    tools_findings.append({
                        "tool_name": tool.name,
                        "tool_description": tool.description,
                        "tool_input_schema": tool.input_schema,
                        "tool_output_schema": tool.output_schema,
                        "vulnerabilities": parsed_vulnerabilities
                    })
            
            # ------------prompts analysis ------------
            if prompts:
                for prompt in prompts:
                    vulnerabilities = self.analyze_prompt(prompt)
                    parsed_vulnerabilities = self.to_dict_list(vulnerabilities)
                    prompts_findings.append({
                        "prompt_name": prompt.name,
                        "prompt_description": prompt.description,
                        "prompt_input_schema": prompt.arguments,
                        "vulnerabilities": parsed_vulnerabilities
                    })
            
            # ------------resources analysis ------------
            if resources:
                for resource in resources:
                    vulnerabilities = self.analyze_resource(resource)
                    parsed_vulnerabilities = self.to_dict_list(vulnerabilities)
                    resources_findings.append({
                        "resource_name": resource.name,
                        "resource_description": resource.description,
                        "resource_size": resource.size,
                        "resource_uri": resource.uri,
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


    def assemble_mcp_recon_context(self):
        """
        Assemble the MCP recon context and return the recon context
        """
        try:
            #TODO : Implement the assemble MCP recon context logic
            pass
        except Exception as e:
            console.print(f"Error in assembling MCP recon context: {e}",style="bold red")
            raise e

    
    def run_agent(self):
        """
        Run the agent
        """
        
        try:
            pass 
            #TODO : Implement the agent logic
        except Exception as e:
            console.print(f"Error in running agent: {e}",style="bold red")
            raise e
    
