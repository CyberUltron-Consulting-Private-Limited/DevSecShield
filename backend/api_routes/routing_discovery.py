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


def discovery_routes(app: FastAPI, engine: Engine):
    
    @app.get("/discovery/conversations",summary="List all discovery scan conversations")
    async def list_sast_scan_conversations(Authorization: Annotated[str | None, Header()] = None):
        """
        List all discovery scan conversations.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # get all discovery scan conversations for the user 🟨
        except Exception as e:
            console.print(f"Error in list_sast_scan_conversations: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.get("/discovery/conversation/{conversation_id}",summary="Get a specific discovery scan conversation")
    async def get_discovery_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Get a specific discovery scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # get the discovery scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in get_discovery_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.post("/discovery/conversation",summary="Create a new discovery scan conversation")
    async def send_messages_to_discovery_scan_conversation(conversation_id: int, messages: list[str], Authorization: Annotated[str | None, Header()] = None):
        """
        Create a new discovery scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # create a new discovery scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in send_messages_to_discovery_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.post("/discovery/conversation/{conversation_id}/message",summary="Send a message to a discovery scan conversation")
    async def send_message_to_discovery_scan_conversation(conversation_id: int, message: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Send a message to a discovery scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # send a message to the discovery scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in send_message_to_discovery_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.delete("/discovery/conversation/{conversation_id}",summary="Delete a discovery scan conversation")
    async def delete_discovery_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Delete a discovery scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # delete the discovery scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in delete_discovery_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.put("/discovery/conversation/{conversation_id}",summary="Update a discovery scan conversation . Use this for renaming the conversation")
    async def update_discovery_scan_conversation(conversation_id: int, name: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Update a discovery scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # update the discovery scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in update_discovery_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    