from __future__ import annotations

import os
from typing import Any, Dict, List
from dotenv import load_dotenv
from rich.console import Console

load_dotenv()

class MissingApiKeyError(Exception):
    pass


from openai import OpenAI
import os
import json
import re

def get_llm_response(content: str, system_prompt: str = "") -> str:

    # Set the API key as an environment variable for the OpenAI client
    api_key = os.getenv("BEDROCK_OPENAI_API_KEY")
    if not api_key:
        raise MissingApiKeyError("Missing BEDROCK_OPENAI_API_KEY for LLM usage (env not set)")
    
    client = OpenAI(
    base_url="https://bedrock-runtime.ap-south-1.amazonaws.com/openai/v1", 
    api_key=api_key # Replace with actual API key
)

    messages = []
    if system_prompt:
        messages.append({
            "role": "system",
            "content": system_prompt
        })
    
    messages.append({
        "role": "user",
        "content": content
    })

    # OpenRouter recommends including referer/title via standard headers; the OpenAI SDK
    # used through OpenRouter doesn't expose header injection here, so prefer llm_json for JSON.
    completion = client.chat.completions.create(model="openai.gpt-oss-20b-1:0", messages=messages, temperature=0.1,response_format={"type": "json_object"})
    return completion.choices[0].message.content

def get_json_llm_response(content: str, system_prompt: str) -> dict:
    """
    Extracts JSON from an LLM response using the httpx-based function.
    
    Args:
        content: The user prompt to send to the LLM
        system_prompt: Optional system prompt to guide the LLM
        
    Returns:
        A dictionary parsed from the JSON in the LLM response
    """
    
    # Use the httpx-based function instead of the OpenAI client
    messages = []
    if system_prompt:
        messages.append({
            "role": "system",
            "content": system_prompt
        })
    
    messages.append({
        "role": "user",
        "content": content
    })
    
    try:
        response = get_llm_response(content, system_prompt)
        
        # Try to extract JSON using regex pattern matching
        json_pattern = r'```(?:json)?\s*([\s\S]*?)\s*```'
        match = re.search(json_pattern, response)
        
        if match:
            # Extract the JSON content from the code block
            json_str = match.group(1)
        else:
            # If no code block is found, try to use the entire response
            json_str = response
        
        try:
            # Parse the JSON string into a Python dictionary
            return json.loads(json_str)
        except json.JSONDecodeError:
            # If parsing fails, return an empty dictionary
            return {}
    except Exception as e:
        Console().print(f"Error: {e}",style="bold red")
        return {}