from langchain_aws import ChatBedrock
import os
from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, Field
from typing import Literal
from rich.console import Console
from fastapi import HTTPException, status
from dotenv import load_dotenv, find_dotenv
import base64
import json
import time

console = Console()

# A developer's local trace file; nothing is written unless DSS_AGENT_DEBUG_LOG is set.
_DEBUG_LOG_PATH = os.environ.get("DSS_AGENT_DEBUG_LOG")


def _agent_debug_log(location: str, message: str, data: dict, hypothesis_id: str, run_id: str = "pre-fix") -> None:
    # #region agent log
    try:
        payload = {
            "sessionId": "dd4a33",
            "runId": run_id,
            "hypothesisId": hypothesis_id,
            "location": location,
            "message": message,
            "data": data,
            "timestamp": int(time.time() * 1000),
        }
        if not _DEBUG_LOG_PATH:
            return
        with open(_DEBUG_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")
    except Exception:
        pass
    # #endregion


def get_llm(
    model: str = "openai.gpt-oss-120b-1:0",
    temperature: float = 0.0,
    max_tokens: int | None = None,
    output_model: type[BaseModel] = None,
    timeout: int = 60*10, # 10 minutes
    ):
    """
    Responsible for getting Bedrock LLM, based on the specified model, temperature, max_tokens
    """
    try:
        load_dotenv()
        aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        aws_region = os.getenv("AWS_DEFAULT_REGION") or "ap-south-1"
        aws_session_token = os.getenv("AWS_SESSION_TOKEN")

        # #region agent log
        _agent_debug_log(
            "llm.py:get_llm",
            "AWS credential resolution before Bedrock client",
            {
                "dotenv_path": find_dotenv() or "NOT_FOUND",
                "key_suffix": aws_access_key[-4:] if aws_access_key and len(aws_access_key) >= 4 else None,
                "secret_len": len(aws_secret_key) if aws_secret_key else 0,
                "has_session_token": bool(aws_session_token),
                "region": aws_region,
                "key_matches_valid_pair": aws_access_key.endswith("4I25") if aws_access_key else False,
                "key_matches_invalid_pair": aws_access_key.endswith("RYEY") if aws_access_key else False,
            },
            hypothesis_id="B",
        )
        # #endregion

        if not aws_access_key or not aws_secret_key:
            raise ValueError("AWS credentials not found")
        
        if output_model:
            llm = ChatBedrock(
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                region=aws_region,
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                model_kwargs={"top_p": 1},
            ).with_structured_output(schema=output_model)
            console.print("Structured Bedrock LLM fetched successfully", style="dim green")
        else:
            llm = ChatBedrock(
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                region=aws_region,
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                model_kwargs={"top_p": 1},
            )
            console.print("Unstructured Bedrock LLM fetched successfully", style="dim green")
        
        return llm
    except Exception as e:
        # #region agent log
        _agent_debug_log(
            "llm.py:get_llm",
            "Bedrock LLM initialization failed",
            {"error_type": type(e).__name__, "error": str(e)},
            hypothesis_id="A",
        )
        # #endregion
        raise ValueError(f"Error in getting LLM: {e}")

def generate_structured_response(input_prompt:str,
                      model:str="openai.gpt-oss-120b-1:0",
                      output_model=None,
                      system_prompt:str=None,
                      image:bytes | None = None)-> BaseModel:
    """
    ### Generates a structued response for text or text + image input. 
    The returned value will be the output_model type model for structured outputs.
    Args :
    - promt : str => is the prompt for generating the response
    - system_prompt : str => system instructions for response generation
    - output_model => the structured output model that will be returned
    - image : bytes => the image bytes
    """
    
    print("📝 Generating Structured response")
    use_native_structured_output = True
    try:
        llm = get_llm(model=model, temperature=0.0, output_model=output_model)
    except ValueError as e:
        if "Structured output is not supported" not in str(e):
            raise
        use_native_structured_output = False
        llm = get_llm(model=model, temperature=0.0, output_model=None)
        console.print(
            "Native structured output unavailable; falling back to JSON schema parsing.",
            style="dim yellow",
        )

    if image:
        print("📷 Image input ")
        image_data = base64.b64encode(image).decode("ascii")
        user_prompt = (
            f"{input_prompt}\n\n"
            "Use the following base64 image payload as supporting evidence while answering:\n"
            f"{image_data}"
        )
    else:
        print("⭐ Pure Text input ")
        user_prompt = input_prompt

    if use_native_structured_output:
        try:
            result = llm.invoke([
                SystemMessage(content=system_prompt or "You are a helpful assistant."),
                HumanMessage(content=user_prompt),
            ])
            # #region agent log
            _agent_debug_log(
                "llm.py:generate_structured_response",
                "Bedrock invoke succeeded",
                {"model": model, "native_structured": True},
                hypothesis_id="A",
            )
            # #endregion
            return result
        except Exception as e:
            # #region agent log
            _agent_debug_log(
                "llm.py:generate_structured_response",
                "Bedrock invoke failed",
                {"model": model, "error_type": type(e).__name__, "error": str(e)},
                hypothesis_id="A",
            )
            # #endregion
            raise

    schema = output_model.model_json_schema() if output_model else {}
    fallback_prompt = (
        f"{user_prompt}\n\n"
        "Return ONLY valid JSON that strictly follows this schema:\n"
        f"{json.dumps(schema)}"
    )
    response = llm.invoke([
        SystemMessage(content=system_prompt or "You are a helpful assistant."),
        HumanMessage(content=fallback_prompt),
    ])

    content = response.content if isinstance(response.content, str) else str(response.content)
    if "<reasoning>" in content and "</reasoning>" in content:
        content = content.split("</reasoning>", 1)[-1].strip()

    start = content.find("{")
    end = content.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("Fallback structured parsing failed: JSON object not found in model response")

    payload = json.loads(content[start : end + 1])
    return output_model.model_validate(payload)

if __name__ == "__main__":
    class Test(BaseModel):
        name: str = Field(description="The name of the person")
        description: str = Field(description="The description of the person")
    result = generate_structured_response(input_prompt="Hello, how are you? im a test person", system_prompt="You are a helpful assistant.", output_model=Test)
    print(result)