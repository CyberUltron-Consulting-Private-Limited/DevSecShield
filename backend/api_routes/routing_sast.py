from typing import Annotated
from fastapi import FastAPI, HTTPException, Header, status
from sqlalchemy.engine import Engine
from sqlmodel import Session, select
from pydantic import BaseModel
from backend.ai_utils.chatbot import create_response
from backend.auth_utils.auth_utils import get_user_from_header_or_raise_exception
from backend.models import User
from backend.auth_utils.plans import plans
import psycopg2
from rich.console import Console
from fastapi.responses import StreamingResponse
from sse_starlette.sse import EventSourceResponse


console = Console()

class SendMessageToSastScanConversationData(BaseModel):
    message_id: str
    user_message: str


def sast_routes(app: FastAPI, engine: Engine):
    
    @app.get("/sast/conversations",summary="List all SAST scan conversations")
    async def list_sast_scan_conversations(Authorization: Annotated[str | None, Header()] = None):
        """
        List all SAST scan conversations.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # get all sast scan conversations for the user 🟨
        except Exception as e:
            console.print(f"Error in list_sast_scan_conversations: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.get("/sast/conversation/{conversation_id}",summary="Get a specific SAST scan conversation")
    async def get_sast_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Get a specific SAST scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # get the sast scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in get_sast_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.post("/sast/conversation",summary="Create a new SAST scan conversation")
    async def send_messages_to_sast_scan_conversation(conversation_id: int, messages: list[str], Authorization: Annotated[str | None, Header()] = None):
        """
        Create a new SAST scan conversation.
        return the conversation id
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # create a new sast scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in send_messages_to_sast_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    
    
    @app.post("/sast/conversation/{conversation_id}/message",summary="Send a message to a SAST scan conversation")
    async def send_message_to_sast_scan_conversation(data: SendMessageToSastScanConversationData,conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Send a message to a SAST scan conversation.
        """
        try:
            # user = await get_user_from_header_or_raise_exception(engine, Authorization)

            # TO DO : if scan is not completed then simply yeild a static response saying "run the scan first"
            
            return EventSourceResponse(create_response(
                message_id=data.message_id,
                scan_type="SAST",
                scan_results="",
                content=data.user_message,
                role="human",
                max_history_length=3,
            ), media_type="text/event-stream")
            # send a message to the sast scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in send_message_to_sast_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    
    @app.get("/sast/conversation/{conversation_id}/scan",summary="Get the scan status of a SAST scan conversation")
    async def get_scan_status_of_sast_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Get the scan status of a SAST scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # get the scan status of the sast scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in get_scan_status_of_sast_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.post("/sast/conversation/{conversation_id}/scan",summary="Start a SAST scan")
    async def start_sast_scan(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Start a SAST scan.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # start the sast scan for the user 🟨
        except Exception as e:
            console.print(f"Error in start_sast_scan: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    
    
    
    
    @app.delete("/sast/conversation/{conversation_id}",summary="Delete a SAST scan conversation")
    async def delete_sast_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Delete a SAST scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # delete the sast scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in delete_sast_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    @app.put("/sast/conversation/{conversation_id}",summary="Update a SAST scan conversation . Use this for renaming the conversation")
    async def update_sast_scan_conversation(conversation_id: int, name: str, Authorization: Annotated[str | None, Header()] = None):
        """
        Update a SAST scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # update the sast scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in update_sast_scan_conversation: {e}")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    