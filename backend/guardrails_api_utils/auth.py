from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from backend.models import User

def check_api_key(api_key: str) -> bool:
    pass

def get_user_from_api_key(api_key: str) -> User:
    pass

api_key_header = APIKeyHeader(name="gr-api-key")

def get_user(api_key_header: str = Security(api_key_header)):
    if check_api_key(api_key_header):
        user = get_user_from_api_key(api_key_header)
        return user
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid Guardrails API key"
    )

def create_api_key() -> str:
    pass