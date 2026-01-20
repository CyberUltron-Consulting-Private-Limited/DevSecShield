# Guardrails API Demo

This folder contains demo files showing how to integrate Guardrails API protection into AI applications.

## Files

### `ai_guardrails_demo.py`
Main demo script showing the difference between processing prompts with and without Guardrails protection.
- Simple, clean code that can be shown to customers
- Demonstrates the workflow clearly

### `guardrails_client.py`
Client library for interacting with the Guardrails API.
- Handles all API communication details
- Functions for scanning prompts and checking results

### `ai_simulation.py`
Simulation module for demonstrating prompt injection attacks.
- **Note**: This file should not be shown to customers
- Contains simulation logic for LLM responses

### `chatbot_demo_server.py`
FastAPI server demonstrating a chatbot with Guardrails protection.
- Two endpoints: one without Guardrails (vulnerable), one with Guardrails (protected)
- Production-ready example for integration

## Quick Start

### Run the Demo Script
```bash
cd guardrails_demo
python ai_guardrails_demo.py
```

### Run the Demo Server
```bash
cd guardrails_demo
python chatbot_demo_server.py
```

Then visit:
- API Documentation: http://localhost:8000/docs
- Root endpoint: http://localhost:8000

## Configuration

Set your Guardrails API key in:
- `ai_guardrails_demo.py` - `GUARDRAILS_API_KEY` variable
- `chatbot_demo_server.py` - `GUARDRAILS_API_KEY` variable

## Example Usage

### Without Guardrails (Vulnerable)
```python
output = llm_api(prompt=unprocessed_prompt)
return output
```

### With Guardrails (Protected)
```python
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
```
