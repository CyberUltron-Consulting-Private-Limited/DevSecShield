import datetime
import os
import sys
from typing import Annotated, Literal
from bson import ObjectId
from celery import Celery
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Header, status
from sqlalchemy.engine import Engine
from sqlmodel import Session, select
from pydantic import BaseModel
from backend.ai_utils.chatbot import create_response
from backend.ai_utils.export_generation import create_export_results
from backend.auth_utils.auth_utils import get_user_from_header_or_raise_exception
from backend.celery_connection import get_celery_app
from backend.models import SASTConversation, User
from backend.auth_utils.plans import plans
import psycopg2
from rich.console import Console
from fastapi.responses import StreamingResponse
from sse_starlette.sse import EventSourceResponse
from pymongo.database import Database
import json
import time
from backend.mongo_models import ActiveContextLog, Conversation, MessageLog
import uuid


console = Console()

class CreateSastScanConversationData(BaseModel):
    title: str

class SendMessageToSastScanConversationData(BaseModel):
    user_message: str

class StartSastScanData(BaseModel):
    repo_url: str
    PAT: str
    app_lang: Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"]


class UpdateSastScanConversationData(BaseModel):
    title: str


def stream_text(text: str):
    text_array = text.split(" ")
    id = str(uuid.uuid4())
    for word in text_array:
        data = {
                "message_id": "Not_allowed_" + id,
                "content": word,
                "reasoning": "",
            }
        yield json.dumps(data)
        time.sleep(0.1)


def sast_routes(app: FastAPI, engine: Engine , mongo_db: Database):
    
    @app.get("/sast/conversations",summary="List all SAST scan conversations")
    async def list_sast_scan_conversations(Authorization: Annotated[str | None, Header()] = None):
        """
        List all SAST scan conversations.
        """
        try:
            # user = await get_user_from_header_or_raise_exception(engine, Authorization)
            user = User(id=1) # for testing purposes
            # get all sast scan conversations for the user 🟨

            # STEP [ 1 ] : =========== get the conversations from the main db ======================
            with Session(engine) as session:
                conversations = None
                conversations = session.exec(select(SASTConversation).where(SASTConversation.user_id == user.id)).all()
                if conversations==None :
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No conversations found")
                console.print(f"Conversations with length: {len(conversations)} found for user: {user.id}" ,style="bold green")
                conversations_data = []
                for conversation in conversations:
                    conversations_data.append({
                        "id": conversation.id,
                        "title": conversation.title,
                        "created_at": conversation.created_at,
                        "last_updated": conversation.last_updated,
                        "scan_status": conversation.scan_status,
                    })
                return conversations_data
        except Exception as e:
            console.print(f"Error in list_sast_scan_conversations: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in fetching conversations , please try again later")
    
    @app.get("/sast/conversation/{conversation_id}",summary="Get a specific SAST scan conversation's messages")
    async def get_sast_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Get a specific SAST scan conversation's messages.
        """
        try:
            # user = await get_user_from_header_or_raise_exception(engine, Authorization)
            user = User(id=1) # for testing purposes
            # get the sast scan conversation for the user 🟨

            # STEP [ 1 ] : =========== get the conversation from the main db to get the conversation id ======================
            conversation = None
            with Session(engine) as session:
                conversation = session.exec(select(SASTConversation).where(SASTConversation.id == conversation_id).where(SASTConversation.user_id == user.id)).first()
                if not conversation:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
            console.print(f"Conversation id: {conversation.id} found in main database" ,style="bold green")
            

            # STEP [ 2 ] : =========== get the conversation from the mongo db to get the conversation id ( for validation )======================
            conversation_collection = mongo_db["conversations"]
            mongo_conversation = None
            mongo_conversation = conversation_collection.find_one({"_id": ObjectId(conversation.conversation_id)})
            if not mongo_conversation:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
            console.print(f"Conversation id: {mongo_conversation['_id']} found in mongo db" ,style="bold green")

            # STEP [ 3 ] : =========== return the messages from the mongo db ======================
            with mongo_db["message_log"].find({"conversation_id": str(mongo_conversation['_id'])}).sort("created_at", 1) as messages:
                messages_data = []
                i = 0
                for message in messages:
                    messages_data.append({
                        "id": i,
                        "content": message["content"],
                        "role": message["sender"],
                        "timestamp": message["created_at"] ,
                        "is_streaming": False,
                    })
                    i += 1
                console.print(f"{len(messages_data)} messages found for conversation: {mongo_conversation['_id']}" ,style="bold green")
                return { "messages": messages_data, }

            
        except Exception as e:
            console.print(f"Error in get_sast_scan_conversation: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in fetching conversation , please try again later")
    
    @app.post("/sast/conversation",summary="Create a new SAST scan conversation")
    async def create_sast_scan_conversation( data: CreateSastScanConversationData, Authorization: Annotated[str | None, Header()] = None):
        """
        Create a new SAST scan conversation.
        return the conversation id
        """
        try:
            # user = await get_user_from_header_or_raise_exception(engine, Authorization)
            user = User(id=1) # for testing purposes
            
            
            # STEP [ 1 ] : =========== create a new conversation id for the mongo db ======================
            conversation_collection = mongo_db["conversations"]
            conversation_instance = Conversation(
                user_id=user.id,
                conv_type="sast",
                title=data.title,
                messages=[],
                message_limit=20,
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            new_conversation= conversation_collection.insert_one(conversation_instance)
            new_conversation_object_id : ObjectId = new_conversation.inserted_id
            new_conversation_id = str(new_conversation_object_id)
            console.print(f"New conversation id: {new_conversation_id} added to mongo db" ,style="bold green")

            
            # STEP [ 2 ] : =========== create a new conversation in the main database ======================
            with Session(engine) as session:
                new_conversation = SASTConversation(
                    user_id=user.id, 
                    title=data.title,
                    conversation_id=new_conversation_id,
                    message_limit=100)
                session.add(new_conversation)
                session.commit()
                session.refresh(new_conversation)
                console.print(f"New conversation id: {new_conversation.id} added to main database" ,style="bold green")
                return {
                    "conversation_id": new_conversation.id,
                    }
            # create a new sast scan conversation for the user 🟨
        except Exception as e:
            console.print(f"Error in send_messages_to_sast_scan_conversation: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in sending message , please try again later")
    
    
    
    @app.post("/sast/conversation/{conversation_id}/message",summary="Send a message to a SAST scan conversation")
    async def send_message_to_sast_scan_conversation(data: SendMessageToSastScanConversationData,conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Send a message to a SAST scan conversation.
        """
        try:
            # user = await get_user_from_header_or_raise_exception(engine, Authorization)
            user = User(id=1) # for testing purposes

            # Note : 
            # Inserting any message into Messages log or Active context log must be done by associating it with : 
            # 1. conversation_id ( mongo db conversation id )
            # 2. user_id ( user id )


            # STEP [ 1 ] : =========== Check if scan has completed by checking the conversation status in the main db and get the results  ======================
            SCAN_RESULTS = None
            with Session(engine) as session:
                conversation = session.exec(select(SASTConversation).where(SASTConversation.id == conversation_id).where(SASTConversation.user_id == user.id)).first()
                if not conversation:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
                if conversation.scan_status != "success" or conversation.scan_data == {} or conversation.scan_data == None or conversation.scan_status == "started" or conversation.scan_status == "failure":
                    return EventSourceResponse(stream_text("Scan is not completed yet, please run the scan first"), media_type="text/event-stream")
                SCAN_RESULTS = conversation.scan_data
            
            if not conversation.conversation_id:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
            
            
            # STEP [ 2 ] : =========== Add the user message to the mongo db ====================== ⭐
            message_collection = mongo_db["message_log"]
            message_instance = MessageLog(
                conversation_id=conversation.conversation_id,
                user_id=user.id,
                content=data.user_message,
                type="message",
                sender="user",
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            result = message_collection.insert_one(message_instance)
            user_message_id = str(result.inserted_id)
            console.print(f"User message added to mongo db" ,style="bold green")
        
            # STEP [ 3 ] : =========== Add user message to the active context log ====================== ⭐
            active_context_collection = mongo_db["active_context"]
            active_context_instance = ActiveContextLog(
                conversation_id=conversation.conversation_id,
                user_id=user.id,
                content=data.user_message,
                type="message",
                sender="user",
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            result = active_context_collection.insert_one(active_context_instance)
            active_context_message_id = str(result.inserted_id)
            console.print(f"User message added to active context log" ,style="bold green")

            # STEP [ 4 ] : =========== Append the mongo db conversation with user message======================
            conversation_collection = mongo_db["conversations"]
            mongo_conversation = conversation_collection.find_one({"_id": ObjectId(conversation.conversation_id)})
            if not mongo_conversation:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
            mongo_conversation["messages"].append(user_message_id) # APPENDED USER MESSAGE INTO CONVERSATION HISTORY LOG 
            conversation_collection.update_one({"_id": ObjectId(conversation.conversation_id)}, {"$set": {"messages": mongo_conversation["messages"]}})
            mongo_conversation_id = str(mongo_conversation["_id"])
            console.print(f"Mongo db conversation array updated with user message" ,style="bold green")



            
            
            
            # STEP [ 5 ] : =========== Get the conversation from the mongo db ======================
            MAX_ACTIVE_HISTORY_LENGTH = 4
            return EventSourceResponse(create_response(
                mongo_conversation_id=mongo_conversation_id,
                user_id=user.id,
                mongo_db=mongo_db,
                scan_type="SAST",
                scan_results=SCAN_RESULTS,
                content=data.user_message,
                role="human",
                max_history_length=MAX_ACTIVE_HISTORY_LENGTH,
            ), media_type="text/event-stream")

           
        except Exception as e:
            console.print(f"Error in send_message_to_sast_scan_conversation: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in sending message , please try again later")
    
    
    @app.get("/sast/conversation/{conversation_id}/scan",summary="Get the scan status of a SAST scan conversation")
    async def get_scan_status_of_sast_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Get the scan status of a SAST scan conversation.
        """
        try:
            # user = await get_user_from_header_or_raise_exception(engine, Authorization)
            user = User(id=1) # for testing purposes
            # get the scan status of the sast scan conversation for the user 🟨

            # STEP [ 1 ] : =========== Get task id ( for celery ) from the main db ======================
            task_id = None
            with Session(engine) as session:
                conversation = session.exec(select(SASTConversation).where(SASTConversation.id == conversation_id).where(SASTConversation.user_id == user.id)).first()
                if not conversation:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
                task_id = conversation.task_id
                if not task_id:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")

            # STEP [ 2 ] : =========== Get the scan status from the celery worker ======================
            simple_app = get_celery_app()
            if simple_app==None:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting celery app , please try again later")
            async_result = simple_app.AsyncResult(task_id)
            celery_status = str(async_result.state).lower()

            # STEP [ 3 ] : =========== Update the main db conversation the scan status ( only when changed )======================
            with Session(engine) as session:
                conversation = session.exec(select(SASTConversation).where(SASTConversation.id == conversation_id)).first()
                if not conversation:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
                # update the scan status only if it has changed
                if conversation.scan_status != celery_status:
                    conversation.scan_status = celery_status
                    session.commit()
                    session.refresh(conversation)
                    console.print(f"Scan with id: {task_id} status updated to {celery_status} in main database" ,style="bold green")
                else:
                    console.print(f"Scan with id: {task_id} status is already {celery_status}, and has not changed . No update needed." ,style="bold green")

            if conversation.scan_status == "success":
                console.print(f"Scan with id: {task_id} status is success" ,style="bold green")
                results = simple_app.AsyncResult(task_id).result
                with Session(engine) as session:
                    conversation = session.exec(select(SASTConversation).where(SASTConversation.id == conversation_id)).first()
                    if not conversation:
                        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
                    # update the scan data only if it is not already set
                    if not conversation.scan_data:
                        console.print(f"Scan with id: {task_id} scan data is not set, updating it" ,style="bold green")
                        conversation.scan_data = results
                        session.commit()
                        session.refresh(conversation)
                        console.print(f"Scan with id: {task_id} scan data updated in main database" ,style="bold green")
                    else:
                        console.print(f"Scan with id: {task_id} scan data is already set, not updating it" ,style="bold green")
                return {
                "scan_status": conversation.scan_status,
                "data": conversation.scan_data,
                }
            else:
                return {
                    "scan_status": conversation.scan_status,
                    "data": None,
                }
            
        except Exception as e:
            console.print(f"Error in get_scan_status_of_sast_scan_conversation: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting scan status , please try again later")
    
    @app.post("/sast/conversation/{conversation_id}/scan",summary="Start a SAST scan")
    async def start_sast_scan(conversation_id: int, data: StartSastScanData, Authorization: Annotated[str | None, Header()] = None):
        """
        Start a SAST scan.
        """
        try:
            # user = await get_user_from_header_or_raise_exception(engine, Authorization)
            user = User(id=1) # for testing purposes
            # start the sast scan for the user 🟨
            
            # STEP [ 1 ] : =========== Validate task  and user allowed to start this conversation ======================
            if not data.repo_url or not data.PAT or not data.app_lang:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid task input")
            if data.app_lang not in ["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"]:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid app language")
            with Session(engine) as session:
                conversation = None
                conversation = session.exec(select(SASTConversation).where(SASTConversation.id == conversation_id).where(SASTConversation.user_id == user.id)).first()
                if conversation==None:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found or User not allowed to start this conversation")
                if conversation.scan_status == "success" or conversation.scan_data != {} or  conversation.scan_status == "started" or conversation.scan_status == "failure" :
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan has already started or completed , cannot start again")
            
            
            # STEP [ 2 ] : =========== Send the task to the celery worker ======================
            simple_app = get_celery_app()
            if simple_app==None:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting celery app , please try again later")
            r = simple_app.send_task(name="scan_worker.sast", kwargs=data.model_dump())

            # STEP [ 3 ] : =========== Update the main db conversation the task id ======================
            with Session(engine) as session:
                conversation = None
                conversation = session.exec(select(SASTConversation).where(SASTConversation.id == conversation_id).where(SASTConversation.user_id == user.id)).first()
                if conversation==None:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found or User not allowed to start this conversation")
                conversation.task_id = r.id
                session.commit()
                session.refresh(conversation)
                return {
                    "message": "Scan started successfully",
                }
        except Exception as e:
            console.print(f"Error in start_sast_scan: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in starting scan , please try again later")
    
    
    
    
    
    @app.delete("/sast/conversation/{conversation_id}",summary="Delete a SAST scan conversation")
    async def delete_sast_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Delete a SAST scan conversation.
        """
        try:
            # user = await get_user_from_header_or_raise_exception(engine, Authorization)
            user = User(id=1) # for testing purposes
            # delete the sast scan conversation for the user 🟨

            # STEP [ 1 ] : =========== Delete the conversation from the main db ======================
            with Session(engine) as session:
                conversation = session.exec(select(SASTConversation).where(SASTConversation.id == conversation_id).where(SASTConversation.user_id == user.id)).first()
                if conversation==None:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not allowed to delete this conversation")
                session.delete(conversation)
                session.commit()
            console.print(f"Conversation id: {conversation.id} deleted from main database" ,style="bold orange3")
            
            # STEP [ 2 ] : =========== Delete the conversation + messages + active contextfrom the mongo db ======================
            conversation_collection = mongo_db["conversations"]
            mongo_conversation = None
            mongo_conversation = conversation_collection.find_one({"_id": ObjectId(conversation.conversation_id)})
            if mongo_conversation==None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
            console.print(f"Conversation id: {mongo_conversation['_id']} found in mongo db" ,style="bold yellow")
            
            
            # STEP [ 2a ] ------------------ Delelte messages with conversation_id -----------------------------
            message_collection = mongo_db["message_log"]
            result = message_collection.delete_many({"conversation_id": str(mongo_conversation['_id'])})
            console.print(f"{result.deleted_count} Messages with conversation_id: {mongo_conversation['_id']} deleted from mongo db" ,style="bold orange3")

            
            
            # STEP [ 2b ] ------------------ Delelte conversation with conversation_id -----------------------------
            conversation_collection.delete_one({"_id": mongo_conversation['_id']})
            console.print(f"Conversation id: {mongo_conversation['_id']} deleted from mongo db" ,style="bold orange3")

            # STEP [ 2c ] ------------------ Delelte active context with conversation_id -----------------------------
            active_context_collection = mongo_db["active_context"]
            result = active_context_collection.delete_many({"conversation_id": str(mongo_conversation['_id'])})
            console.print(f"{result.deleted_count} Active context with conversation_id: {mongo_conversation['_id']} deleted from mongo db" ,style="bold orange3")



            console.print(f"Conversation id: {conversation.id} deleted from main database and conversation id: {mongo_conversation['_id']} deleted along with messages from mongo db" ,style="bold green")
            return {
                "message": "Conversation deleted successfully",
            }
                
        except Exception as e:
            console.print(f"Error in delete_sast_scan_conversation: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in deleting conversation , please try again later")
    
    @app.put("/sast/conversation/{conversation_id}",summary="Update a SAST scan conversation . Use this for renaming the conversation")
    async def update_sast_scan_conversation(conversation_id: int, data: UpdateSastScanConversationData, Authorization: Annotated[str | None, Header()] = None):
        """
        Update a SAST scan conversation.
        """
        try:
            # user = await get_user_from_header_or_raise_exception(engine, Authorization)
            user = User(id=1) # for testing purposes
            # update the sast scan conversation for the user 🟨

            # STEP [ 1 ] : =========== Update the main db conversation the title ======================
            with Session(engine) as session:
                conversation = session.exec(select(SASTConversation).where(SASTConversation.id == conversation_id)).first()
                if not conversation:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not allowed to update this conversation")
                conversation.title = data.title
                session.commit()
                session.refresh(conversation)
                return {
                    "message": "Conversation title updated successfully",
                }
        except Exception as e:
            console.print(f"Error in update_sast_scan_conversation: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in updating conversation , please try again later")
    
    @app.get("/sast/conversation/{conversation_id}/export",summary="Export the results of a SAST scan conversation")
    async def export_sast_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Export the results of a SAST scan conversation.
        """
        try:
            # user = await get_user_from_header_or_raise_exception(engine, Authorization)
            user = User(id=1) # for testing purposes

            
            export_results = None
            
            # STEP [ 1 ] : ======================= Get the conversation from main db and check if export_results is already populated ========================================
            conversation = None
            with Session(engine) as session:
                conversation = session.exec(select(SASTConversation).where(SASTConversation.id == conversation_id).where(SASTConversation.user_id == user.id)).first()
                if not conversation:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
                if conversation.export_results:
                    export_results = conversation.export_results

                
            # STEP [ 2 ] : ======================= Export the results of the conversation if export data is not already populated ========================================
            if not export_results:
                export_results = create_export_results(conversation.scan_data)
            
                # STEP [ 3 ] : ======================= Update the main db conversation the export_results ======================
                with Session(engine) as session:
                    conversation = session.exec(select(SASTConversation).where(SASTConversation.id == conversation_id).where(SASTConversation.user_id == user.id)).first()
                    if not conversation:
                        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not allowed to export this conversation")
                    conversation.export_results = export_results
                    session.commit()
                    session.refresh(conversation)
                    console.print(f"Export results for conversation id: {conversation.id} updated in main database" ,style="bold green")
                    
            
            if export_results:
                return {"data": export_results}
            else:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Export results not found")
            
        
        except Exception as e:
            console.print(f"Error in export_sast_scan_conversation: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in exporting conversation , please try again later")
    