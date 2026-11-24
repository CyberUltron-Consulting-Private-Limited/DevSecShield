from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    judge_model: str = Field(default="gpt-4o")
    judge_base_url: str = Field(default="https://api.openai.com/v1")
    ollama_url: str = Field(default="http://localhost:11434")
