from pydantic import Field , BaseModel
from typing import Literal, Optional
from helpers.context.base_agent import BaseAgent
from rich.console import Console

console = Console()
def generate_dependency_diagram(
        architecture_description:str,
        ):
    
    
    class Node(BaseModel):
        id : int = Field(description="ID for this node.")
        label : str = Field(description="An informative label of this node")
        children : "Optional[list[Node]]" = Field(description="list of Children of this node") 
    
    class Tree(BaseModel):
        root_node : list[Node] = Field(description="The root node of the diagram. There can be more than one root node too")
    
    system_prompt="""You are a cybersecurity expert with 20 years of experience.
    You must analyze the below details given about the architecture of an IAC codebase and create a dependency diagram of the infrastructure (resources and their dependencies).
    Each node is an IAC resource or module; children are resources that depend on the parent.
    
    example format (root_node = list of top-level nodes with no dependents):
{
    "root_node": [
        {
            "id": 1,
            "label": "aws_vpc.main",
            "children": [
                {
                    "id": 2,
                    "label": "aws_subnet.public",
                    "children": [
                        {
                            "id": 3,
                            "label": "aws_instance.app_server",
                            "children": []
                        }
                    ]
                },
                {
                    "id": 4,
                    "label": "aws_security_group.allow_http",
                    "children": []
                }
            ]
        }
    ]
}
    """
    prompt = f"""
    {architecture_description}
    """

    base_agent = BaseAgent()
    response = base_agent.generate_structured_response(prompt=prompt,
                                            system_prompt=system_prompt,
                                            output_model=Tree)
    tree = response.model_dump()
    console.print(f"Tree: {tree}",style="dim orange1")

    code = convert_tree_to_mermaid(tree_data=tree)
    print(f"Code: {code}")

    return code
    
def convert_tree_to_mermaid(tree_data):
    """
    Convert structured tree data to Mermaid syntax.
    
    Args:
        tree_data (dict): Dictionary containing the tree structure
        
    Returns:
        str: Mermaid diagram code
    """
    mermaid_lines = ["graph TD"]
    
    def process_node(node, parent_id=None):
        print(node)
        node_id = node["id"]
        node_label = node["label"]
        
        # Add quotes if label contains spaces or parentheses
        if " " in node_label or "(" in node_label or ")" in node_label:
            node_label = f'"{node_label}"'
        
        # Add the node definition
        mermaid_lines.append(f'    {node_id}[{node_label}]')
        
        # Add connection to parent if exists
        if parent_id:
            mermaid_lines.append(f'    {parent_id} --> {node_id}')
        
        # Process children
        if "children" in node and node["children"]:
            for child in node["children"]:
                process_node(child, node_id)
    
    # Process the root node(s)
    for root_node in tree_data["root_node"]:
        process_node(root_node)
    
    # Join lines with newlines
    return "\n".join(mermaid_lines)




