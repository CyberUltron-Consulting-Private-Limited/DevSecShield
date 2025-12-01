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


def gitleaks_routes(app: FastAPI, engine: Engine):
    
    @app.get("/gitleaks/conversations",summary="List all gitleaks scan conversations")
    async def list_gitleaks_scan_conversations(Authorization: Annotated[str | None, Header()] = None):
        """
        List all gitleaks scan conversations.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # get all gitleaks scan conversations for the user 🟨
        except Exception as e:
            console.print(f"Error in list_gitleaks_scan_conversations: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.get("/gitleaks/conversation/{conversation_id}",summary="Get a specific gitleaks scan conversation")
    async def get_gitleaks_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Get a specific gitleaks scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # get the gitleaks scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in get_gitleaks_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.post("/gitleaks/conversation",summary="Create a new gitleaks scan conversation")
    async def send_messages_to_gitleaks_scan_conversation(conversation_id: int, messages: list[str], Authorization: Annotated[str | None, Header()] = None):
        """
        Create a new gitleaks scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # create a new gitleaks scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in send_messages_to_gitleaks_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.post("/gitleaks/conversation/{conversation_id}/message",summary="Send a message to a gitleaks scan conversation")
    async def send_message_to_gitleaks_scan_conversation(conversation_id: int, message: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Send a message to a gitleaks scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # send a message to the gitleaks scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in send_message_to_gitleaks_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.delete("/gitleaks/conversation/{conversation_id}",summary="Delete a gitleaks scan conversation")
    async def delete_sast_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Delete a gitleaks scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # delete the gitleaks scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in delete_sast_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.put("/gitleaks/conversation/{conversation_id}",summary="Update a gitleaks scan conversation . Use this for renaming the conversation")
    async def update_sast_scan_conversation(conversation_id: int, name: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Update a gitleaks scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # update the gitleaks scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in update_sast_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    