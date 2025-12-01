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


def llm_routes(app: FastAPI, engine: Engine):
    
    @app.get("/iac/conversations",summary="List all IAC scan conversations")
    async def list_iac_scan_conversations(Authorization: Annotated[str | None, Header()] = None):
        """
        List all IAC scan conversations.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # get all iac scan conversations for the user 🟨
        except Exception as e:
            console.print(f"Error in list_iac_scan_conversations: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.get("/iac/conversation/{conversation_id}",summary="Get a specific IAC scan conversation")
    async def get_iac_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Get a specific IAC scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # get the iac scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in get_iac_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.post("/iac/conversation",summary="Create a new IAC scan conversation")
    async def send_messages_to_iac_scan_conversation(conversation_id: int, messages: list[str], Authorization: Annotated[str | None, Header()] = None):
        """
        Create a new IAC scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # create a new iac scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in send_messages_to_iac_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.post("/iac/conversation/{conversation_id}/message",summary="Send a message to a IAC scan conversation")
    async def send_message_to_iac_scan_conversation(conversation_id: int, message: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Send a message to a IAC scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # send a message to the iac scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in send_message_to_iac_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.delete("/iac/conversation/{conversation_id}",summary="Delete a IAC scan conversation")
    async def delete_iac_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Delete a IAC scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # delete the iac scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in delete_iac_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.put("/iac/conversation/{conversation_id}",summary="Update a IAC scan conversation . Use this for renaming the conversation")
    async def update_iac_scan_conversation(conversation_id: int, name: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Update a IAC scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # update the iac scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in update_iac_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    