from helpers.tools.llm_agent.main import LLMBenchmarkingAgent
from helpers.tools.llm_agent.context import LLMBenchmarkingContext
from rich.console import Console
import json
console = Console()

if __name__ == "__main__":
    model_type="custom"
    model_name="gpt-4o"
    headers:dict = {
            "Authorization": "Bearer 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",
            "Content-Type": "application/json"
            }
    request_template={
        "model": "gpt-4o",
        "input": "$INPUT"
        }
    response_json_field="$.output[0].content[0].text"
    probes=["malwaregen.Evasion" , "malwaregen.TopLevel"]
    model_uri="https://api.openai.com/v1/responses"

    llm_benchmarking_context = LLMBenchmarkingContext(
        model_type=model_type,
        model_name=model_name,
        headers=headers,
        request_template=request_template,
        response_json_field=response_json_field,
        probes=probes,
        model_uri=model_uri,
    )

    llm_benchmarking_agent = LLMBenchmarkingAgent( llm_benchmarking_context=llm_benchmarking_context )

    vulnerabilities = llm_benchmarking_agent.run_agent()


    with open("llm_agent_results_testing.json", "w") as f:
        json.dump(vulnerabilities, f, indent=2)

    console.print(f"LLM Agent Results saved to llm_agent_results_testing.json",style="bold green")