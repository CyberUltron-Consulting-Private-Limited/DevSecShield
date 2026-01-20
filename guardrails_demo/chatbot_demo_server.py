"""
Chatbot Demo Server with Guardrails Protection

This FastAPI server demonstrates a chatbot with and without Guardrails protection.
Use this to show customers how Guardrails protects AI applications.

Endpoints:
- POST /chat/without-guardrails - Chat endpoint without protection (vulnerable)
- POST /chat/with-guardrails - Chat endpoint with Guardrails protection (secure)
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
from guardrails_client import (
    start_guardrails_scan_and_wait_for_results,
    passed_check,
    get_sanitized_prompt
)
from ai_simulation import llm_api

app = FastAPI(
    title="Chatbot Demo API",
    description="Demo API showing chatbot with and without Guardrails protection",
    version="1.0.0"
)

# Configuration - Set your API key here
GUARDRAILS_API_KEY = "Bearer gr1-10d5ee8e90b2eef4c96b87c024265bb08a6809399255e4d9ebdeb39a9a5cd0d5ffccf02ed57353d768bf795366327e521d5ae5347203ab7d01e636b9c095eb00"


class ChatRequest(BaseModel):
    """Request model for chat endpoints."""
    message: str


class ChatResponse(BaseModel):
    """Response model for chat endpoints."""
    response: str
    status: str


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "message": "Chatbot Demo API",
        "description": "Demonstrates chatbot with and without Guardrails protection",
        "endpoints": {
            "/chat/without-guardrails": "POST - Chat endpoint without Guardrails (vulnerable)",
            "/chat/with-guardrails": "POST - Chat endpoint with Guardrails protection (secure)"
        }
    }


@app.post("/chat/without-guardrails", response_model=ChatResponse)
async def chat_without_guardrails(request: ChatRequest):
    """
    Chat endpoint WITHOUT Guardrails protection.
    
    This endpoint is vulnerable to prompt injection attacks.
    User prompts are sent directly to the LLM without any security checks.
    
    Example request:
    {
        "message": "What is the weather today?"
    }
    """
    try:
        # Process prompt directly without any protection
        user_prompt = request.message
        
        # Call LLM directly (no protection)
        llm_response = llm_api(prompt=user_prompt)
        
        return ChatResponse(
            response=llm_response,
            status="success"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing request: {str(e)}")


@app.post("/chat/with-guardrails", response_model=ChatResponse)
async def chat_with_guardrails(request: ChatRequest):
    """
    Chat endpoint WITH Guardrails protection.
    
    This endpoint is protected against prompt injection attacks.
    User prompts are scanned by Guardrails before being sent to the LLM.
    
    Example request:
    {
        "message": "What is the weather today?"
    }
    """
    try:
        # Get user prompt
        user_prompt = request.message
        print(f"\n📥 Received user message: {user_prompt[:100]}{'...' if len(user_prompt) > 100 else ''}")
        
        # Step 1: Scan prompt with Guardrails
        scan_results = start_guardrails_scan_and_wait_for_results(
            api_key=GUARDRAILS_API_KEY,
            input_prompt=user_prompt
        )
        
        # Step 2: Check if prompt passed Guardrails scan
        if not passed_check(scan_results):
            print("🚫 Request blocked - malicious input detected\n")
            return ChatResponse(
                response="Input is flagged as malicious, therefore blocked",
                status="blocked"
            )
        
        # Step 3: Get sanitized prompt
        sanitized_prompt = get_sanitized_prompt(scan_results, user_prompt)
        if sanitized_prompt != user_prompt:
            print(f"📝 Using sanitized prompt: {sanitized_prompt[:100]}{'...' if len(sanitized_prompt) > 100 else ''}")
        
        # Step 4: Call LLM with sanitized prompt
        print("📤 Sending prompt to LLM...")
        llm_response = llm_api(prompt=sanitized_prompt)
        print("✅ LLM response received\n")
        
        return ChatResponse(
            response=llm_response,
            status="success"
        )
    except Exception as e:
        print(f"❌ Error processing request: {e}\n")
        raise HTTPException(status_code=500, detail=f"Error processing request: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
