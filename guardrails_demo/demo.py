"""
Guardrails API Demo Script

This script demonstrates the difference between:
1. Using an AI prompt without Guardrails (direct prompt)
2. Using an AI prompt with Guardrails protection (sanitized prompt)

Before running, set your API key:
    GUARDRAILS_API_KEY = "Bearer YOUR_API_KEY"
"""

from guardrails_client import (
    start_guardrails_scan_and_wait_for_results,
    passed_check,
    get_sanitized_prompt
)
from ai_simulation import llm_api, PROMPT_INJECTION_ATTACKS

# Configuration
GUARDRAILS_API_KEY = "Bearer gr1-10d5ee8e90b2eef4c96b87c024265bb08a6809399255e4d9ebdeb39a9a5cd0d5ffccf02ed57353d768bf795366327e521d5ae5347203ab7d01e636b9c095eb00"


# Example 1: Without Guardrails
def process_without_guardrails(unprocessed_prompt: str):
    """Process prompt without Guardrails protection."""
    output = llm_api(prompt=unprocessed_prompt)
    return output


# Example 2: With Guardrails
def process_with_guardrails(unprocessed_prompt: str):
    """Process prompt with Guardrails protection."""
    scan_results = start_guardrails_scan_and_wait_for_results(
        api_key=GUARDRAILS_API_KEY,
        input_prompt=unprocessed_prompt
    )
    
    if passed_check(scan_results):
        sanitized_prompt = get_sanitized_prompt(scan_results, unprocessed_prompt)
        output = llm_api(prompt=sanitized_prompt)
        return output
    else:
        return "Input is flagged as malicious, therefore blocked"


def main():
    """Main function to run the demo."""
    # Use a malicious prompt injection attack for demonstration
    malicious_prompt = PROMPT_INJECTION_ATTACKS[0]
    
    print("=" * 70)
    print("Example 1: WITHOUT Guardrails")
    print("=" * 70)
    print(f"\nPrompt: {malicious_prompt}\n")
    result1 = process_without_guardrails(malicious_prompt)
    print(f"Output: {result1}\n")
    
    print("\n" + "=" * 70)
    print("Example 2: WITH Guardrails")
    print("=" * 70)
    print(f"\nPrompt: {malicious_prompt}\n")
    result2 = process_with_guardrails(malicious_prompt)
    print(f"Output: {result2}\n")


if __name__ == "__main__":
    main()
