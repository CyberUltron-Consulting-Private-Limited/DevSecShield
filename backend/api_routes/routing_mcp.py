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


def mcp_routes(app: FastAPI, engine: Engine):
    
    @app.get("/mcp/conversations",summary="List all MCP scan conversations")
    async def list_mcp_scan_conversations(Authorization: Annotated[str | None, Header()] = None):
        """
        List all MCP scan conversations.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # get all mcp scan conversations for the user 🟨
        except Exception as e:
            console.print(f"Error in list_mcp_scan_conversations: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.get("/mcp/conversation/{conversation_id}",summary="Get a specific MCP scan conversation")
    async def get_mcp_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Get a specific MCP scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # get the mcp scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in get_mcp_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.post("/mcp/conversation",summary="Create a new MCP scan conversation")
    async def send_messages_to_mcp_scan_conversation(conversation_id: int, messages: list[str], Authorization: Annotated[str | None, Header()] = None):
        """
        Create a new MCP scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # create a new mcp scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in send_messages_to_mcp_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.post("/mcp/conversation/{conversation_id}/message",summary="Send a message to a MCP scan conversation")
    async def send_message_to_mcp_scan_conversation(conversation_id: int, message: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Send a message to a MCP scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # send a message to the mcp scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in send_message_to_mcp_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.delete("/mcp/conversation/{conversation_id}",summary="Delete a MCP scan conversation")
    async def delete_mcp_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Delete a MCP scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # delete the mcp scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in delete_mcp_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.put("/mcp/conversation/{conversation_id}",summary="Update a MCP scan conversation . Use this for renaming the conversation")
    async def update_mcp_scan_conversation(conversation_id: int, name: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Update a MCP scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # update the mcp scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in update_mcp_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    