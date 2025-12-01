from typing import Annotated
from fastapi import FastAPI, HTTPException, Header, status
from sqlalchemy.engine import Engine
from sqlmodel import Session, select
from pydantic import BaseModel
from backend.auth_utils.auth_utils import get_user_from_header_or_raise_exception
from backend.models import User
from backend.auth_utils.plans import plans
import psycopg2
from rich.console import Console


console = Console()


def sca_sbom_routes(app: FastAPI, engine: Engine):
    
    @app.get("/sca_sbom/conversations",summary="List all SCA SBOM scan conversations")
    async def list_sca_sbom_scan_conversations(Authorization: Annotated[str | None, Header()] = None):
        """
        List all SCA SBOM scan conversations.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # get all sca sbom scan conversations for the user 🟨
        except Exception as e:
            console.print(f"Error in list_sca_sbom_scan_conversations: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.get("/sca_sbom/conversation/{conversation_id}",summary="Get a specific SCA SBOM scan conversation")
    async def get_sca_sbom_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Get a specific SCA SBOM scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # get the sca sbom scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in get_sca_sbom_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.post("/sca_sbom/conversation",summary="Create a new SCA SBOM scan conversation")
    async def send_messages_to_sca_sbom_scan_conversation(conversation_id: int, messages: list[str], Authorization: Annotated[str | None, Header()] = None):
        """
        Create a new SCA SBOM scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # create a new sca sbom scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in send_messages_to_sca_sbom_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.post("/sca_sbom/conversation/{conversation_id}/message",summary="Send a message to a SCA SBOM scan conversation")
    async def send_message_to_sca_sbom_scan_conversation(conversation_id: int, message: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Send a message to a SCA SBOM scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # send a message to the sca sbom scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in send_message_to_sca_sbom_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.delete("/sca_sbom/conversation/{conversation_id}",summary="Delete a SCA SBOM scan conversation")
    async def delete_sca_sbom_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Delete a SCA SBOM scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # delete the sca sbom scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in delete_sca_sbom_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.put("/sca_sbom/conversation/{conversation_id}",summary="Update a SCA SBOM scan conversation . Use this for renaming the conversation")
    async def update_sca_sbom_scan_conversation(conversation_id: int, name: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Update a SCA SBOM scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # update the sca sbom scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in update_sca_sbom_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    