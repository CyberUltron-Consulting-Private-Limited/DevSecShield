import secrets
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from backend.new_models import GuardrailsIntegration
from sqlmodel import Session, select
from backend.get_db import get_db
from rich.console import Console
console = Console()

def get_user_and_integration_from_api_key(api_key: str) -> tuple[int, int]:
    try:
        engine = get_db(dev_environment=True)
        with Session(engine) as session:
            integration = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.api_key == api_key)).first()
            if not integration:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Guardrails API key")
            return (integration.user_id, integration.id)
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Guardrails API key")

api_key_header = APIKeyHeader(name="gr-api-key")

def get_user_and_integration_id(api_key_header: str = Security(api_key_header)):
    """
    Get the user from the API key header
    Args:
        api_key_header: str
    Returns:
        User
    Raises:
        HTTPException: 401 if the API key is missing or invalid
    Example:
        >>> user = get_user("gr1-weasjdfbwejf12313ksdnc")
        >>> print(user.email)
        >>> nikhil@cyberultron.com
    """
    try:
        api_key = api_key_header.split(" ")[1]
        user_id, integration_id = get_user_and_integration_from_api_key(api_key)
        if not user_id or not integration_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Guardrails API key")
        
        console.print(f"User ID: {user_id}, Integration ID: {integration_id} has accessed the API with API key ******{api_key[-6:]}", style="bold yellow")
        return {
            "user_id": user_id,
            "integration_id": integration_id
        }
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Guardrails API key")



def create_api_key(team_id: int) -> str:
    """
    Create a new API key for a user
    Args:
        team_id: int
    Returns:
        str: The new API key
    Raises:
        HTTPException: 401 if the user is missing or invalid
    Example:
        >>> api_key = create_api_key(team_id=1)
        >>> print(api_key)
        >>> gr1-weasjdfbwejf12313ksdnc
    """
    try:
        return "gr" + str(team_id) + "-" + secrets.token_hex(64) # example : gr1-weasjdfbwejf12313ksdnc
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Error creating Guardrails API key")