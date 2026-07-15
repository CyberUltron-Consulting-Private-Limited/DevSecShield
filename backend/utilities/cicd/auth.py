import secrets
import hashlib
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from backend.new_models import CicdIntegration
from sqlmodel import Session, select
from backend.get_db import get_db
from rich.console import Console
console = Console()


def hash_api_key(api_key: str) -> str:
    """Create a SHA-256 hash of the API key for secure storage/lookup."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def get_user_integration_team_from_api_key(api_key: str) -> tuple[int, int, int]:
    """
    Validate API key and return user_id, integration_id, team_id.
    Supports both legacy plaintext keys and new hashed keys.
    """
    try:
        engine = get_db()
        api_key_hash = hash_api_key(api_key)
        
        with Session(engine) as session:
            # First try: lookup by hash (new secure method)
            integration = session.exec(
                select(CicdIntegration).where(
                    CicdIntegration.api_key == api_key_hash
                )
            ).first()
            
            # Fallback: legacy plaintext lookup (for migration period)
            if not integration:
                integration = session.exec(
                    select(CicdIntegration).where(
                        CicdIntegration.api_key == api_key
                    )
                ).first()
            
            if not integration:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, 
                    detail="Missing or invalid CI/CD API key"
                )
            return (integration.owner_user_id, integration.id, integration.team_id)
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Missing or invalid CI/CD API key"
        )

api_key_header = APIKeyHeader(name="cicd-api-key")

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
        >>> user = get_user("cicd1-weasjdfbwejf12313ksdnc")
        >>> print(user.email)
        >>> nikhil@cyberultron.com
    """
    try:
        api_key = api_key_header.strip()
        user_id, integration_id, team_id = get_user_integration_team_from_api_key(api_key)
        if not user_id or not integration_id or not team_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid CI/CD API key")
        
        console.print(f"User ID: {user_id}, Integration ID: {integration_id} has accessed the API with API key ******{api_key[-6:]}", style="bold yellow")
        return {
            "user_id": user_id,
            "integration_id": integration_id,
            "team_id": team_id
        }
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid CI/CD API key")



def create_api_key(team_id: int) -> tuple[str, str]:
    """
    Create a new API key for a team's CI/CD integration.
    
    Returns:
        tuple: (plaintext_api_key, hashed_api_key)
        - plaintext_api_key: Show to user ONCE, never stored
        - hashed_api_key: Store in database for secure lookup
    
    Example:
        >>> plaintext_key, hashed_key = create_api_key(team_id=1)
        >>> # Store hashed_key in DB, show plaintext_key to user once
    """
    try:
        plaintext_key = "cicd" + str(team_id) + "-" + secrets.token_hex(64)
        hashed_key = hash_api_key(plaintext_key)
        return (plaintext_key, hashed_key)
    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Error creating CI/CD API key"
        )