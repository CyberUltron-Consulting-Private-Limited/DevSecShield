from context import TicketingIntegrationContext
from rich.console import Console
from ticketing.jira import create_issue_in_project as create_issue_in_jira


def create_issue_in_for_results(
    input_prompt: str,
    results: list[dict], 
    ticketing_integration_context: TicketingIntegrationContext)-> None:
    try:
        console = Console()
        findings_description = ""
        for key,value in results.items():
            if key in [ "Anonymize" , "Toxicity" , "Tokenlimit" , "Promptinjection" , "Regex" , "Code" , "Secrets" ]:
                if value["score"] > 0.9:
                    findings_description += f"Critical Risk identified in the {key} Scanner, Risk Score : {value['score']}\n"
                elif value["score"] > 0.7 and value["score"] <= 0.9:
                    findings_description += f"High Risk identified in the {key} Scanner, Risk Score : {value['score']}\n"
                elif value["score"] > 0.5 and value["score"] <= 0.7:
                    findings_description += f"Medium Risk identified in the {key} Scanner, Risk Score : {value['score']}\n"
                else:
                    continue # not a critical risk 
        
        if findings_description == "":
            console.print(f"No critical risks found in the results",style="bold yellow")
            return
        else:
            findings_description = f"Input Prompt : {input_prompt}\n\n" + findings_description
        
        if ticketing_integration_context.jira:
            project_id = ticketing_integration_context.jira.jira_project_id
            api_token = ticketing_integration_context.jira.jira_api_token
            url = ticketing_integration_context.jira.jira_url
            email = ticketing_integration_context.jira.jira_email
            
            create_issue_in_jira(
                project_id=project_id,
                jira_token=api_token,
                jira_url=url,
                jira_email=email,
                issue_type="Task",
                summary="Guardrails Detected Risky Input",
                description=findings_description,
            )
        
        return 
    except Exception as e:
        console.print(f"Error in creating issue for results: {e}",style="bold red")
        raise e