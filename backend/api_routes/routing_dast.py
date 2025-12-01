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


def dast_routes(app: FastAPI, engine: Engine):
    
    @app.get("/dast/conversations",summary="List all DAST scan conversations")
    async def list_dast_scan_conversations(Authorization: Annotated[str | None, Header()] = None):
        """
        List all DAST scan conversations.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # get all dast scan conversations for the user 🟨
        except Exception as e:
            console.print(f"Error in list_dast_scan_conversations: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.get("/dast/conversation/{conversation_id}",summary="Get a specific DAST scan conversation")
    async def get_dast_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Get a specific DAST scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # get the dast scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in get_dast_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.post("/dast/conversation",summary="Create a new DAST scan conversation")
    async def send_messages_to_dast_scan_conversation(conversation_id: int, messages: list[str], Authorization: Annotated[str | None, Header()] = None):
        """
        Create a new DAST scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # create a new dast scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in send_messages_to_dast_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.post("/dast/conversation/{conversation_id}/message",summary="Send a message to a DAST scan conversation")
    async def send_message_to_dast_scan_conversation(conversation_id: int, message: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Send a message to a DAST scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # send a message to the dast scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in send_message_to_dast_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.delete("/dast/conversation/{conversation_id}",summary="Delete a DAST scan conversation")
    async def delete_dast_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Delete a DAST scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # delete the dast scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in delete_dast_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.put("/dast/conversation/{conversation_id}",summary="Update a DAST scan conversation . Use this for renaming the conversation")
    async def update_dast_scan_conversation(conversation_id: int, name: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Update a DAST scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # update the dast scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in update_dast_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    