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

        result = agent.run_agent()
    except Exception as e:
        console.print(f"Error while Testing SAST agent : {str(e)}")