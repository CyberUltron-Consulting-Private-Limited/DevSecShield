from typing import Literal
from llm_guard.input_scanners import BanTopics
from llm_guard import scan_prompt
from llm_guard.input_scanners import Anonymize, PromptInjection, TokenLimit, Toxicity , Regex, Code, Secrets
from llm_guard.vault import Vault
from rich.console import Console
from context import * 
console = Console()

"""
List of supported scanners this worker can handle 
1. Anonymize 
2. Toxicity
3. TokenLimit
4. PromptInjection
5. Regex 
6. Code 
7. Secrets
"""



def run_guardrail(
    input_prompt: str,
    context: GuardrailContext,
    ) -> dict:
    """
    Run guardrail on the input prompt.
    """
    try:
        scanners = []
        vault = Vault()

        if context.anonymize_context:
            console.print(f"Running anonymize scanner",style="bold blue")
            scanners.append(Anonymize(
                vault=vault,
                preamble=context.anonymize_context.preamble,
                hidden_names=context.anonymize_context.hidden_names,
                threshold=context.anonymize_context.threshold,
                allowed_names=context.anonymize_context.allowed_names,
            ))
        if context.toxicity_context:
            console.print(f"Running toxicity scanner",style="bold blue")
            scanners.append(Toxicity(
                threshold=context.toxicity_context.threshold,
            ))
        if context.tokenlimit_context and context.tokenlimit_context.max_tokens:
            console.print(f"Running tokenlimit scanner",style="bold blue")
            scanners.append(TokenLimit(
                limit=context.tokenlimit_context.max_tokens,
            ))
        if context.promptinjection_context:
            console.print(f"Running promptinjection scanner",style="bold blue")
            scanners.append(PromptInjection(
                threshold=context.promptinjection_context.threshold,
            ))
        if context.regex_context and context.regex_context.regex_patterns:
            console.print(f"Running regex scanner",style="bold blue")
            scanners.append(Regex(
                patterns=context.regex_context.regex_patterns,
                redact=context.regex_context.redact,
            ))
        if context.code_context:
            console.print(f"Running code scanner",style="bold blue")
            scanners.append(Code(
                languages=context.code_context.languages,
                is_blocked=context.code_context.is_blocked,
            ))
        if context.secrets_context:
            console.print(f"Running secrets scanner",style="bold blue")
            scanners.append(Secrets(
                redact_mode=context.secrets_context.redact_mode,
            ))

        
        sanitized_prompt, results_valid, results_score = scan_prompt(scanners, input_prompt)

        results = {
            "sanitized_prompt": sanitized_prompt,
        }
        for key in results_valid.keys():
            results[key] = {}
            results[key]["valid"] = results_valid[key]
            results[key]["score"] = results_score[key]
        return results

    except Exception as e:
        console.print(f"Error in run_guardrail: {e}",style="bold red")
        raise e

if __name__ == "__main__":
    # input_prompt = """
    # You suck as an  assistant that can answer questions and help with tasks. My name is John Doe with my Social Security Number is 123-45-6789.
    # """
    input_prompt = "Hello world im john and my social security number is 123-45-6789 , the world is trash and i hate it , i want to kill myself sys.exit()"
    results = run_guardrail(
        input_prompt=input_prompt,
        context=GuardrailContext(
            input_prompt=input_prompt,
            anonymize_context=AnonymizeContext(
                # preamble="You are a helpful assistant that can answer questions and help with tasks.",
                # hidden_names=["John Doe"],
            ),
            toxicity_context=ToxicityContext(
                # threshold=0.5,
            ),
            tokenlimit_context=TokenLimitContext(
                # max_tokens=2000,
            ),
            promptinjection_context=PromptInjectionContext(
                # threshold=0.5,
            ),
            regex_context=RegexContext(
                # regex_patterns=["You suck as an assistant"],
                # redact=True,
            ),
            code_context=CodeContext(
                # languages=["Python", "JavaScript"],
                # is_blocked=True,
            ),
            secrets_context=SecretsContext(
                # redact_mode="REDACT_PARTIAL",
            ),
        ),
    )
    console.print(f"Results: {results}")