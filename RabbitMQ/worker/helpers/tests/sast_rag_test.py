from helpers.context.scan_context import GithubContext, validate_dict_with_context
from helpers.tools import SASTAgent , SASTSummaryManager
from rich.console import Console

console = Console()

if __name__ == "__main__":
    
    try:
        # testing repository integration with sast agent 
        dict_context = {
        "mode":"github",
        "repo_url":"https://github.com/CyberUltron-Nikhil/RiskPilot.git",
        "PAT":"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",
        }
        context = validate_dict_with_context(dict_context)

        agent = SASTAgent(
            context=context,
            app_lang="python",
            exclude_path_arrays=[["frontend"],["api_routes"],["mcpscan_utils"],["llm_scan_utils"]]
        )

        # agent.populate_codebase_context()
        # console.print(f"codebase context id : {agent.codebase_context_id}",style="bold yellow")

        # agent.populate_opensource_context()

        # console.print(f"codebase context id : {agent.codebase_context_id}",style="bold yellow")
        
        # console.print(f"opensource context id : {agent.opensource_context_id}",style="bold yellow")

        docs = agent.query_vector_store(
            vector_store=agent.get_vector_store("codebase_context"),
            k=3,
            query="authentication",
            metadata_filter = { "context_id" : "1a295a62-f638-4557-9ee5-53e6c2e1219c20260121120752" }
        )

        console.print(f"Hits : \n{docs}")
    except Exception as e:
        console.print(f"Error while Testing SAST agent : {str(e)}")