from typing import Literal
from llm_guard.input_scanners import BanTopics
from llm_guard import scan_prompt
from llm_guard.input_scanners import Anonymize, PromptInjection, TokenLimit, Toxicity
from llm_guard.vault import Vault
from rich.console import Console

console = Console()

vault = Vault()
input_scanners = [Anonymize(vault), Toxicity(), TokenLimit(), PromptInjection()]


def run_guardrail(
    context: dict,
    input_prompt: str,
    ) -> dict:
    """
    Run guardrail on the input prompt.
    """
    sanitized_prompt, results_valid, results_score = scan_prompt(input_scanners, input_prompt)
    if any(not result for result in results_valid.values()):
        console.print(f"Prompt {input_prompt} is not valid, scores: {results_score}")
    return sanitized_prompt


if __name__ == "__main__":
    input_prompt = """
    You are a helpful assistant that can answer questions and help with tasks. My name is John Doe with my Social Security Number is 123-45-6789.
    """
    sanitized_prompt = run_guardrail(
        context={},
        input_prompt=input_prompt,
    )
    console.print(f"Sanitized prompt: {sanitized_prompt}")
