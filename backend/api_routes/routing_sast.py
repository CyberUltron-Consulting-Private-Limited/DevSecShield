import datetime
from typing import Annotated, Literal
from bson import ObjectId
from fastapi import FastAPI, HTTPException, Header, status
from sqlalchemy.engine import Engine
from sqlmodel import Session, select
from pydantic import BaseModel
from backend.ai_utils.chatbot import create_response
from backend.ai_utils.export_generation import create_export_results
from backend.auth_utils.auth_utils import get_user_from_header_or_raise_exception
from backend.celery_connection import get_celery_app, get_status_and_update_db
from backend.models import SASTConversation, User
from backend.auth_utils.plans import plans
from rich.console import Console
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
    mode: Literal["github", "gitlab", "bitbucket"]
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
                "content": word + " ",
                "reasoning": "",
            }
        yield json.dumps(data)
        time.sleep(0.1)

def get_messages_from_conversation(conversation_id: int,user_id: int, engine: Engine, mongo_db: Database):
    try:

        # STEP [ 1 ] : =========== get the conversation from the main db to get the conversation id ======================
        conversation = None
        with Session(engine) as session:
            conversation = session.exec(select(SASTConversation).where(SASTConversation.id == conversation_id).where(SASTConversation.user_id == user_id)).first()
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
            return messages_data

        
    except Exception as e:
        console.print(f"Error in get_sast_scan_conversation: {e}",style="bold red")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in fetching conversation , please try again later")


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
                for conversation in conversations:   #there is no logic here to update and check status of scan ( maybe will add later if required )
                    conversations_data.append({
                        "id": conversation.id,
                        "repo_url": conversation.repo_url,
                        "mode": conversation.mode,
                        "title": conversation.title,
                        "created_at": conversation.created_at,
                        "last_updated": conversation.last_updated,
                        "scan_status": conversation.scan_status.lower(),
                    })
                return conversations_data
        except Exception as e:
            console.print(f"Error in list_sast_scan_conversations: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in fetching conversations , please try again later")
    
        
    
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

            CONVERSATION = None
            MESSAGE_LIMIT = None
            SCAN_DATA = {}


            # STEP [ 1 ] : =========== Get the conversation from the main db ======================
            with Session(engine) as session:
                conversation = session.exec(select(SASTConversation).where(SASTConversation.id == conversation_id).where(SASTConversation.user_id == user.id)).first()
                if not conversation:
                    console.print(f"Conversation id: {conversation_id} not found in main database" ,style="bold red")
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found ")
                
                MESSAGE_LIMIT = conversation.message_limit
                CONVERSATION = conversation
                SCAN_STATUS = conversation.scan_status
                SCAN_DATA = conversation.scan_data
            

            # STEP [ 2 ] : =========== Check if conversation can be updated with new status and scan data  ======================
            # if conversation.scan_status == "pending" or conversation.scan_status == "NOT_STARTED" or conversation.scan_data == {}:
            #     FETCHED_STATUS , FETCHED_SCAN_DATA , FETCHED_CONVERSATION = get_status_and_update_db(conversation_id, None, SASTConversation, engine)
            #     CONVERSATION = FETCHED_CONVERSATION if FETCHED_CONVERSATION else CONVERSATION # update the conversation if it is not found in the main db
            #     SCAN_DATA = FETCHED_SCAN_DATA if FETCHED_SCAN_DATA else SCAN_DATA # update the scan data if it is not found in the main db
            #     SCAN_STATUS = FETCHED_STATUS if FETCHED_STATUS else SCAN_STATUS # update the scan status if it is not found in the main db

            if not CONVERSATION:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
            if not SCAN_DATA or SCAN_DATA == {} or SCAN_STATUS == "pending" or SCAN_STATUS == "NOT_STARTED" or SCAN_STATUS != "success":
                return EventSourceResponse(stream_text("Scan status or scan data is not valid, please run the scan first"), media_type="text/event-stream")

            
            # STEP [ 3 ] : =========== Add the user message to the mongo db ====================== ⭐
            message_collection = mongo_db["message_log"]

            #checking length of message log for this conversation 
            message_log_length = message_collection.count_documents({"conversation_id": CONVERSATION.conversation_id})
            if message_log_length + 2 >= MESSAGE_LIMIT:
                return EventSourceResponse(stream_text("Message limit reached, please delete some messages to add new ones"), media_type="text/event-stream")

            message_instance = MessageLog(
                conversation_id=CONVERSATION.conversation_id,
                user_id=user.id,
                content=data.user_message,
                type="message",
                sender="user",
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            result = message_collection.insert_one(message_instance)
            user_message_id = str(result.inserted_id)
            console.print(f"User message added to mongo db" ,style="bold green")
        
            # STEP [ 4 ] : =========== Add user message to the active context log ====================== ⭐
            active_context_collection = mongo_db["active_context"]
            active_context_instance = ActiveContextLog(
                conversation_id=CONVERSATION.conversation_id,
                user_id=user.id,
                content=data.user_message,
                type="message",
                sender="user",
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            result = active_context_collection.insert_one(active_context_instance)
            active_context_message_id = str(result.inserted_id)
            console.print(f"User message added to active context log with id: {active_context_message_id}" ,style="bold green")

            # STEP [ 5 ] : =========== Append the mongo db conversation with user message======================
            conversation_collection = mongo_db["conversations"]
            mongo_conversation = conversation_collection.find_one({"_id": ObjectId(CONVERSATION.conversation_id)})
            if not mongo_conversation:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
            mongo_conversation["messages"].append(user_message_id) # APPENDED USER MESSAGE INTO CONVERSATION HISTORY LOG 
            conversation_collection.update_one({"_id": ObjectId(CONVERSATION.conversation_id)}, {"$set": {"messages": mongo_conversation["messages"]}})
            mongo_conversation_id = str(mongo_conversation["_id"])
  
            
            
            # STEP [ 5 ] : =========== Get the conversation from the mongo db ======================
            MAX_ACTIVE_HISTORY_LENGTH = 4
            return EventSourceResponse(create_response(
                mongo_conversation_id=mongo_conversation_id,
                user_id=user.id,
                mongo_db=mongo_db,
                scan_type="SAST",
                scan_results=SCAN_DATA,
                content=data.user_message,
                role="human", # doesnt get saved to any db , jsut for functional clarity 
                max_history_length=MAX_ACTIVE_HISTORY_LENGTH,
            ), media_type="text/event-stream")

           
        except Exception as e:
            console.print(f"Error in send_message_to_sast_scan_conversation: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in sending message , please try again later")
    
    
    @app.get("/sast/conversation/{conversation_id}",summary="Get the scan status of a SAST scan conversation")
    async def get_sast_scan_conversation(conversation_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Get the scan status of a SAST scan conversation.
        """
        try:
            # user = await get_user_from_header_or_raise_exception(engine, Authorization)
            user = User(id=1) # for testing purposes
            # get the scan status of the sast scan conversation for the user 🟨
            SCAN_STATUS = None
            MESSAGES = None
            SCAN_DATA = None
            TASK_ID = None


            # STEP [ 1 ] : =========== Get task id ( for celery ) from the main db ======================

            with Session(engine) as session:
                conversation = session.exec(select(SASTConversation).where(SASTConversation.id == conversation_id).where(SASTConversation.user_id == user.id)).first()
                if not conversation:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
                TASK_ID = conversation.task_id
                SCAN_STATUS = conversation.scan_status
                SCAN_DATA = conversation.scan_data


            # STEP [ 2 ] : =================== Get the scan status from the celery worker if scan is not completed yet ======================
            console.print(f"SCAN_STATUS: {SCAN_STATUS} TASK_ID: {TASK_ID}",style="bold yellow")
            if (SCAN_STATUS == "pending" or SCAN_STATUS == "NOT_STARTED" or SCAN_DATA == {}) and (TASK_ID != None) and (TASK_ID != ""):
                FETCHED_SCAN_STATUS , FETCHED_SCAN_DATA , conversation = get_status_and_update_db(conversation_id, TASK_ID, SASTConversation, engine)
                SCAN_STATUS = FETCHED_SCAN_STATUS if FETCHED_SCAN_STATUS else SCAN_STATUS
                SCAN_DATA = FETCHED_SCAN_DATA if FETCHED_SCAN_DATA else SCAN_DATA
            
            # STEP [ 3 ] : =================== Fetching messages if scan is completed ======================
            MESSAGES = get_messages_from_conversation(conversation_id, user.id, engine, mongo_db)


            if not SCAN_STATUS :
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan status or scan data or messages not found")
            
            return {
                "title": conversation.title,
                "repo_url": conversation.repo_url,
                "scan_status": SCAN_STATUS.lower(),
                "data": SCAN_DATA,
                "messages": MESSAGES,
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
                if conversation.scan_status == "success" or conversation.scan_data != {} or  conversation.scan_status == "started" or conversation.scan_status == "failure":
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan has already started or completed , cannot start again")
                if conversation.scan_status == "pending" :
                    FETCHED_STATUS , FETCHED_DATA , FETCHED_CONVERSATION = get_status_and_update_db(conversation_id, None, SASTConversation, engine)
                    if FETCHED_STATUS == "success" or FETCHED_STATUS == "started" or FETCHED_STATUS == "failure" or FETCHED_STATUS == "pending" or FETCHED_DATA != {} :
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan has already started or completed , cannot start again")
            
            
            
            # STEP [ 2 ] : =========== Send the task to the celery worker ======================
            simple_app = get_celery_app()
            if simple_app==None:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting celery app , please try again later")
            kwargs ={
                "dict_context":{
                    "mode":data.mode,
                    "repo_url":data.repo_url,
                    "PAT":data.PAT,
                },
                "app_lang":data.app_lang,
            }
            r = simple_app.send_task(name="scan_worker.sast", kwargs=kwargs)

            # STEP [ 3 ] : =========== Update the main db conversation the task id ======================
            with Session(engine) as session:
                conversation = None
                conversation = session.exec(select(SASTConversation).where(SASTConversation.id == conversation_id).where(SASTConversation.user_id == user.id)).first()
                if conversation==None:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found or User not allowed to start this conversation")
                conversation.mode = data.mode
                conversation.repo_url = data.repo_url
                conversation.task_id = r.id
                conversation.app_lang = data.app_lang
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

            
            
            # STEP [ 2b ] ------------------ Delete conversation with conversation_id -----------------------------
            conversation_collection.delete_one({"_id": mongo_conversation['_id']})
            console.print(f"Conversation id: {mongo_conversation['_id']} deleted from mongo db" ,style="bold orange3")

            # STEP [ 2c ] ------------------ Delete active context with conversation_id -----------------------------
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
    