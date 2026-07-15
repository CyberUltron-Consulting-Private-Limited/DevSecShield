from helpers.tools.iac_agent.diagram import generate_dependency_diagram

if __name__ == "__main__":
    architecture_description = """
    IAC Dependency Architecture description :
    The codebase is a simple IAC codebase that creates a VPC, Subnet, Instance, and Security Group.
    The VPC is the parent resource and the Subnet, Instance, and Security Group are the child resources.
    The Subnet is dependent on the VPC and the Instance is dependent on the Subnet.
    The Security Group is dependent on the Instance.
    """
    code = generate_dependency_diagram(architecture_description)
    # print(code)