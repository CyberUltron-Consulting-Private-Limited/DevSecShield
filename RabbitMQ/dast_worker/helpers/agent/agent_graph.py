from typing import Annotated, TypedDict
from langchain.prompts import PromptTemplate
from langgraph.graph import StateGraph, START, END
from langgraph.graph.state import CompiledStateGraph
from typing import Literal
from rich.console import Console
from helpers.agent.BaseUtilities import BaseUtilities
from pydantic import BaseModel, Field
from helpers.schema import DASTVulnerability , FinalVulnResponse 
from helpers.agent.BaseSummaryManager import BaseSummaryManager
from helpers.checks.nuclei.run_nuclei import run_nuclei
from helpers.checks.nuclei.yaml_validate import strip_markdown_fences, validate_nuclei_yaml
from operator import add
import tempfile
from langchain_core.documents import Document
from IPython.display import Image, display
from langsmith import traceable
import os

console = Console(markup=False)

class StrategyGenerationOutput(BaseModel):
    strategy : str = Field(description="The strategy to generate a headless nuclei template to exploit the specified vulnerability")

class NucleiTemplateGenerationOutput(BaseModel):
    template_yaml_content : str = Field(description="The YAML file content for the headless nuclei template to exploit the specified vulnerability . Important : The template must be in the format of a YAML file and must be a valid headless nuclei template. No other text should be present in the template , only generate the YAML file content ")

class NucleiTemplateValidationOutput(BaseModel):
    template_valid : bool = Field(description="Whether the template is valid or not")
    reason : str | None = Field(description="The reason for the template validation result , let this be None if the template is valid")

class OverallState(TypedDict):
    # to be provided as input to the graph 
    target_url : str 
    page_content : str 
    strategy_generation_system_prompt : str 
    strategy_generation_prompt : str # this prompt must have a {page_content} variable to be replaced with the page content
    nuclei_template_generation_system_prompt : str 
    nuclei_template_generation_prompt : str # this prompt must have a {strategy} variable to be replaced with the strategy
    nuclei_template_validation_system_prompt : str 
    nuclei_template_validation_prompt : str # this prompt must have a {template} variable to be replaced with the template
    summary_manager : BaseSummaryManager


    # states to be updated by nodes
    exploit_retries_left : int = 2 
    current_strategy : str | None = None 
    current_template : str | None = None  # YAML file content for the headless nuclei template
    template_valid : bool = False 
    validation_retries_left : int = 2 
    template_validation_reason : str | None = None 
    nuclei_timeout_seconds : int 
    egress_proxy : str | None  # the scan's SOCKS5 egress guard (helpers/net/egress.py); nuclei never runs without it

    vulnerabilities : Annotated[list[DASTVulnerability],add] = []


@traceable(name="Generate strategy")
def generate_strategy(state : OverallState) -> OverallState:
    """
    This Node is responsible for generating a strategy to exploit the specified vulnerability 
    based on the page content provided.
    """
    try:
        console.print(f"========================== Strategy Generation Node ==================================",style="dim cyan")
        base_utilities = BaseUtilities()

        prompt_template = PromptTemplate( input_variables=["page_content"], template=state["strategy_generation_prompt"] )
        prompt = prompt_template.format(page_content=state["page_content"])

        if state["current_strategy"] : # only active if exploit did not generate any vulnerabilities ( not active during first generation )
            temp = f"""
            \n\n
            The Previous Strategy generated was not able to exploit the vulnerability based on the page content provided.
            \n
            Please generate a new strategy that is able to exploit the vulnerability based on the page content provided.
            Previous Strategy : {state["current_strategy"]}
            \n
            Previous Nuclei Template Generated : {state["current_template"]}
            """
            prompt += temp
        
        strategy_output : type[StrategyGenerationOutput] = base_utilities.generate_structured_response(
            prompt=prompt,
            system_prompt=state["strategy_generation_system_prompt"],
            output_model=StrategyGenerationOutput,
        )
        
        console.print(f"Strategy generated successfully:\n{strategy_output.strategy}",style="dim green")
        

        return {"current_strategy": strategy_output.strategy}
        
    except Exception as e:
        console.print(f"Error generating strategy: {e}",style="dim red")
        raise e


@traceable(name="Generate template")
def generate_template(state : OverallState) -> OverallState:
    """
    This Node is responsible for generating a headless nuclei template to exploit the specified vulnerability 
    based on the strategy generated by the previous node.
    """
    try:
        console.print(f"========================== Nuclei Template Generation Node ==================================",style="dim cyan")

        base_utilities = BaseUtilities()

        prompt_template_string = state["nuclei_template_generation_prompt"]

        if state["template_validation_reason"] : # only active if template validation was rejected ( not active during first generation )
            temp = f"""
            \n\n
            The Previos Template generate was rejected with the following reason: {state["template_validation_reason"]}
            \n
            Please generate a new template that is valid and does not have the same issues.
            """
            console.print(f"Template validation failure reason: {state['template_validation_reason']}",style="dim red")
            prompt_template_string += temp


        prompt_template = PromptTemplate( input_variables=["strategy"], template=prompt_template_string )
        prompt = prompt_template.format(strategy=state["current_strategy"])
        template_output : type[NucleiTemplateGenerationOutput] = base_utilities.generate_structured_response(
            prompt=prompt,
            system_prompt=state["nuclei_template_generation_system_prompt"],
            output_model=NucleiTemplateGenerationOutput,
        )
        
        yaml_len = len(template_output.template_yaml_content or "")
        console.print(f"Template generated successfully ({yaml_len} bytes)", style="dim green")
       
        
        return {"current_template": template_output.template_yaml_content , "validation_retries_left": state["validation_retries_left"] - 1}
    
    except Exception as e:
        console.print(f"Error generating template: {e}",style="dim red")
        raise e

@traceable(name="Validate template")
def validate_template(state : OverallState) -> OverallState:
    """
    Local YAML validation. An extra Bedrock round-trip here used to add 10–20s
    per XSS/SQLi attempt without catching anything yaml.safe_load misses.
    """
    try:
        console.print(f"========================== Nuclei Template Validation Node ==================================",style="dim cyan")
        cleaned = strip_markdown_fences(state.get("current_template") or "")
        if not cleaned:
            console.print("No template generated yet",style="dim red")
            return {"template_valid": False, "template_validation_reason": "empty template"}
        ok, reason = validate_nuclei_yaml(cleaned)
        console.print(f"Template validated successfully:\n{ok}",style="dim green")
        if ok:
            return {
                "current_template": cleaned,
                "template_valid": True,
                "template_validation_reason": None,
            }
        return {"template_valid": False, "template_validation_reason": reason}
    except Exception as e:
        console.print(f"Error validating template: {e}",style="dim red")
        raise e

@traceable(name="Execute template and Find vulnerabilities")
def execute_template(state : OverallState) -> OverallState:
    """
    This Node is responsible for executing the headless nuclei template generated by the previous node.
    It will execute the template and return the result.
    """
    try:
        console.print(f"========================== Nuclei Template Execution Node ==================================",style="dim cyan")
        
        template_path = tempfile.NamedTemporaryFile(delete=False,suffix=".yaml")
        with open(template_path.name, "w+") as f:
            f.write(state["current_template"])
        
        result_documents : list[Document] = run_nuclei(
            template_path=template_path.name,
            url=state["target_url"],
            timeout_seconds=int(state.get("nuclei_timeout_seconds") or 90),
            egress_proxy=state.get("egress_proxy"),
        )

        if not result_documents:
            console.print("Nuclei returned no documents; skipping LLM summary", style="dim yellow")
            return {"vulnerabilities": [] , "exploit_retries_left": state["exploit_retries_left"] - 1}

        # assess document and see if there are any vulnerabilities found
        base_utilities = BaseUtilities(documents=result_documents)
        summary : type[FinalVulnResponse] = base_utilities.generate_map_reduce_summary(summary_manager=state["summary_manager"])


        console.print(f"Number of vulnerabilities found: {len(summary.vulnerabilities)}",style="dim green")
        console.print("======"*10,style="dim cyan")

        try:
            #cleanup the temporary file
            template_path.close()
        except Exception as e:
            console.print(f"Error cleaning up temporary file: {e}",style="dim red")
            pass

        if summary.vulnerabilities:
            return {"vulnerabilities": summary.vulnerabilities , "exploit_retries_left": state["exploit_retries_left"] - 1}
        else:
            console.print("No vulnerabilities found",style="dim red")
            return {"vulnerabilities": [] , "exploit_retries_left": state["exploit_retries_left"] - 1}
        
    except Exception as e:
        console.print(f"Error executing template: {e}",style="dim red")
        return {"vulnerabilities": [] , "exploit_retries_left": state["exploit_retries_left"] - 1}

def exploit_success_edge(state : OverallState) -> str: # will return the node name to retry
    if state["exploit_retries_left"] > 0 and len(state["vulnerabilities"]) == 0:
        return "generate_strategy"
    else:
        return END



def yaml_template_validation_edge(state : OverallState) -> str: # will return the node name to retry
    if not state["template_valid"] and state["validation_retries_left"] > 0:
        return "generate_template"
    else:
        return "execute_template"



def build_graph() -> CompiledStateGraph[OverallState]:
    try:
        builder = StateGraph(OverallState)

        # add nodes to the graph
        builder.add_node("generate_strategy", generate_strategy)
        builder.add_node("generate_template", generate_template)
        builder.add_node("validate_template", validate_template)
        builder.add_node("execute_template", execute_template)


        # add edges to the graph
        builder.add_edge(START, "generate_strategy")
        builder.add_edge("generate_strategy", "generate_template")
        builder.add_edge("generate_template", "validate_template")

        builder.add_conditional_edges("validate_template", yaml_template_validation_edge)
        builder.add_conditional_edges("execute_template", exploit_success_edge)


        # complile the graph
        graph = builder.compile()


        return graph

    except Exception as e:
        console.print(f"Error building graph: {e}",style="dim red")
        raise e
