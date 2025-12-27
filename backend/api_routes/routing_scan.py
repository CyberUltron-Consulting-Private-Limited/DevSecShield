import datetime
import os
import tempfile
from typing import Annotated, Literal
from bson import ObjectId
from fastapi import FastAPI, HTTPException, Header, status, BackgroundTasks, Depends
from fastapi.responses import FileResponse
from sqlalchemy.engine import Engine
from sqlmodel import Sequence, Session, select
from pydantic import BaseModel
from backend.ai_utils.chatbot import create_response
from backend.ai_utils.export_generation import create_export_results
from backend.auth_utils.auth_utils import get_user_from_header_or_raise_exception
from backend.celery_connection import get_celery_app, get_status_and_update_db
from backend.models import SASTConversation, User , LLMBenchmarkingConversation
from backend.auth_utils.plans import plans
from rich.console import Console
from sse_starlette.sse import EventSourceResponse
from fastapi.responses import StreamingResponse
from pymongo.database import Database
import json
import time
from backend.mongo_models import ActiveContextLog, Conversation, MessageLog
import uuid
from backend.api_routes.functions import * 
from backend.pdf_utils.sast_pdf import generate_pdf as generate_sast_pdf
from backend.pdf_utils.llm_pdf import generate_pdf as generate_llm_pdf
from backend.pdf_utils.mcp_pdf import generate_pdf as generate_mcp_pdf
from backend.pdf_utils.iac_pdf import generate_pdf as generate_iac_pdf
from backend.pdf_utils.gitleaks_pdf import generate_pdf as generate_gitleaks_pdf
from backend.pdf_utils.sbom_sca_pdf import generate_pdf as generate_sbom_sca_pdf
from backend.pdf_utils.agent_discovery_pdf import generate_pdf as generate_agent_discovery_pdf
from fastapi_throttle import RateLimiter


console = Console()




def scan_routes(app: FastAPI, engine: Engine , mongo_db: Database):

    limiter = RateLimiter(times=20, seconds=30) # 20 requests per 30 seconds
    
    @app.get("/{type}/conversations",summary="List all scan conversations")
    async def list_scan_conversations(type: scan_types, background_tasks: BackgroundTasks, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
        """
        List all scan conversations.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # user = User(id=1) # for testing purposes

            Table = get_Table_from_type(type)


            # STEP [ 1 ] : =========== get the conversations from the main db ======================
            with Session(engine) as session:
                conversations = None
                conversations = session.exec(select(Table).where(Table.user_id == user.id).order_by(Table.created_at.desc())).all()
                if conversations==None :
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No conversations found")
                console.print(f"{len(conversations)} {type} conversations found for user: {user.id}" ,style="bold green")
                conversations_data,conversations_to_update = return_conversations_list_for_type(type, conversations)

                if len(conversations_to_update) > 0:
                    background_tasks.add_task(update_status_of_conversation_in_main_db, conversations_to_update, user.id, type, engine)
                    console.print(f"Background task added to update statuses of conversations: {conversations_to_update}" ,style="bold green")
                
                return conversations_data
        except Exception as e:
            console.print(f"Error in list_{type}_scan_conversations: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in fetching conversations , please try again later")
    
        
    
    @app.post("/{type}/conversation",summary="Create a new scan conversation")
    async def create_scan_conversation( data: CreateScanConversationData, type: scan_types, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
        """
        Create a new scan conversation.
        return the conversation id
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # user = User(id=1) # for testing purposes
            Table = get_Table_from_type(type)
            
            
            # STEP [ 1 ] : =========== create a new conversation id for the mongo db ======================
            conversation_collection = mongo_db["conversations"]
            conversation_instance = Conversation(
                user_id=user.id,
                conv_type=type,
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
                new_conversation = Table(
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
            console.print(f"Error in create_{type}_scan_conversation: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in sending message , please try again later")
    
    
    
    @app.post("/{type}/conversation/{conversation_id}/message",summary="Send a message to a scan conversation")
    async def send_message_to_scan_conversation(type: scan_types, data: SendMessageToScanConversationData,conversation_id: int, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
        """
        Send a message to a scan conversation.
        Note : 
            Inserting any message into Messages log or Active context log must be done by associating it with : 
            1. conversation_id ( mongo db conversation id )
            2. user_id ( user id )
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # user = User(id=1) # for testing purposes

            Table = get_Table_from_type(type)


            CONVERSATION = None
            MESSAGE_LIMIT = None
            SCAN_DATA = {}


            # STEP [ 1 ] : =========== Get the conversation from the main db ======================
            with Session(engine) as session:
                conversation = session.exec(select(Table).where(Table.id == conversation_id).where(Table.user_id == user.id)).first()
                if not conversation:
                    console.print(f"Conversation id: {conversation_id} not found in main database" ,style="bold red")
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found ")
                
                #updating last_updated field
                conversation.last_updated = datetime.datetime.now(datetime.timezone.utc)
                session.commit()
                session.refresh(conversation)
                
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
            if not SCAN_DATA or SCAN_DATA == {} or SCAN_STATUS == "pending" or SCAN_STATUS == "NOT_STARTED" or SCAN_STATUS == "started" or SCAN_STATUS != "success":
                return EventSourceResponse(stream_text("Scan has not run or hasn't completed yet, please wait for the scan to complete if it has been initiated or start the scan"), media_type="text/event-stream")

            
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
                scan_type=type,
                scan_results=SCAN_DATA,
                content=data.user_message,
                role="human", # doesnt get saved to any db , jsut for functional clarity 
                max_history_length=MAX_ACTIVE_HISTORY_LENGTH,
            ), media_type="text/event-stream")

           
        except Exception as e:
            console.print(f"Error in send_message_to_{type}_scan_conversation: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in sending message , please try again later")
    
    
    @app.get("/{type}/conversation/{conversation_id}",summary="Get the scan status of a scan conversation")
    async def get_scan_conversation(type: scan_types, conversation_id: int, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
        """
        Get the scan status of a scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # user = User(id=1) # for testing purposes
            Table = get_Table_from_type(type)
            SCAN_STATUS = None
            MESSAGES = None
            SCAN_DATA = None
            TASK_ID = None


            # STEP [ 1 ] : =========== Get task id ( for celery ) from the main db ======================

            with Session(engine) as session:
                conversation = session.exec(select(Table).where(Table.id == conversation_id).where(Table.user_id == user.id)).first()
                if not conversation:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
                TASK_ID = conversation.task_id
                SCAN_STATUS = conversation.scan_status
                SCAN_DATA = conversation.scan_data


            # STEP [ 2 ] : =================== Get the scan status from the celery worker if scan is not completed yet ======================
            console.print(f"SCAN_STATUS: {SCAN_STATUS} TASK_ID: {TASK_ID}",style="bold yellow")
            if (SCAN_STATUS == "pending" or SCAN_STATUS == "NOT_STARTED" or SCAN_DATA == {} or SCAN_STATUS == "started") and (TASK_ID != None) and (TASK_ID != ""):
                FETCHED_SCAN_STATUS , FETCHED_SCAN_DATA , conversation = get_status_and_update_db(
                    conversation_id=conversation_id,
                    task_id=TASK_ID,
                    table=Table,
                    engine=engine
                )
                SCAN_STATUS = FETCHED_SCAN_STATUS if FETCHED_SCAN_STATUS else SCAN_STATUS
                SCAN_DATA = FETCHED_SCAN_DATA if FETCHED_SCAN_DATA else SCAN_DATA
            
            # STEP [ 3 ] : =================== Fetching messages if scan is completed ======================
            MESSAGES = get_messages_from_conversation(
                conversation_id=conversation_id,
                user_id=user.id,
                Table=Table,
                engine=engine,
                mongo_db=mongo_db
            )


            if not SCAN_STATUS :
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan status or scan data or messages not found")
            
            return return_conversation_data(
                conversation=conversation,
                type=type,
                SCAN_STATUS=SCAN_STATUS,
                SCAN_DATA=SCAN_DATA,
                MESSAGES=MESSAGES,
            )
            
        except Exception as e:
            console.print(f"Error in get_scan_status_of_{type}_scan_conversation: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in getting scan status , please try again later")
    
    @app.post("/{type}/conversation/{conversation_id}/scan",summary="Start a scan")
    async def start_scan(
        type: scan_types,
        conversation_id: int, 
        sast_data: StartSastScanData | None = None,
        llm_data: StartLLMBenchmarkingData | None = None,
        mcp_data: StartMCPScanData | None = None,
        iac_data: StartGeneralScanData | None = None,
        leakage_data: StartGeneralScanData | None = None,
        sbom_sca_data: StartGeneralScanData | None = None,
        agent_discovery_data: StartGeneralScanData | None = None,
        dast_data: StartDASTScanData | None = None,
        Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
        """
        Start a scan.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # user = User(id=1) # for testing purposes
            Table = get_Table_from_type(type)
            
            # STEP [ 1 ] : =========== Validate getting the conversation from the main db ======================
            
            with Session(engine) as session:
                conversation = None
                conversation = session.exec(select(Table).where(Table.id == conversation_id).where(Table.user_id == user.id)).first()
                if conversation==None:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found or User not allowed to start this conversation")
                if conversation.scan_status == "success" or conversation.scan_status == "started" or conversation.scan_data != {} or  conversation.scan_status == "started" or conversation.scan_status == "failure":
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan has already started or completed , cannot start again")
                if (conversation.scan_status == "pending" or conversation.scan_status == "NOT_STARTED" or conversation.scan_status == "started") and (conversation.task_id != None) and (conversation.task_id != "") :
                    FETCHED_STATUS , FETCHED_DATA , FETCHED_CONVERSATION = get_status_and_update_db(
                        conversation_id=conversation_id,
                        task_id=conversation.task_id,
                        table=Table,
                        engine=engine
                    )
                    if FETCHED_STATUS == "success" or FETCHED_STATUS == "started" or FETCHED_STATUS == "failure" or FETCHED_STATUS == "pending" or FETCHED_DATA != {} :
                        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan has already started or completed , cannot start again")
            
            
                start_scan_and_update_db(
                    sast_data=sast_data,
                    llm_data=llm_data,
                    mcp_data=mcp_data,
                    iac_data=iac_data,
                    leakage_data=leakage_data,
                    sbom_sca_data=sbom_sca_data,
                    agent_discovery_data=agent_discovery_data,
                    dast_data=dast_data,
                    conversation_id=conversation_id,
                    user_id=user.id,
                    engine=engine,
                    mongo_db=mongo_db,
                    type=type,
                    table=Table,
                )
           
                return {
                    "message": "Scan started successfully",
                }
        except Exception as e:
            console.print(f"Error in start_{type}_scan: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in starting scan , please try again later")
    
    
    
    
    
    @app.delete("/{type}/conversation/{conversation_id}",summary="Delete a scan conversation")
    async def delete_scan_conversation(type: scan_types, conversation_id: int, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
        """
        Delete a scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # user = User(id=1) # for testing purposes
            Table = get_Table_from_type(type)

            # STEP [ 1 ] : =========== Delete the conversation from the main db ======================
            with Session(engine) as session:
                conversation = session.exec(select(Table).where(Table.id == conversation_id).where(Table.user_id == user.id)).first()
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
            console.print(f"Error in delete_{type}_scan_conversation: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in deleting conversation , please try again later")
    
    @app.put("/{type}/conversation/{conversation_id}",summary="Update a scan conversation . Use this for renaming the conversation")
    async def update_scan_conversation(type: scan_types, conversation_id: int, data: UpdateScanConversationData, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)]):
        """
        Update a scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # user = User(id=1) # for testing purposes
            Table = get_Table_from_type(type)

            # STEP [ 1 ] : =========== Update the main db conversation the title ======================
            with Session(engine) as session:
                conversation = session.exec(select(Table).where(Table.id == conversation_id)).first()
                if not conversation:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not allowed to update this conversation")
                conversation.title = data.title
                session.commit()
                session.refresh(conversation)
                return {
                    "message": "Conversation title updated successfully",
                }
        except Exception as e:
            console.print(f"Error in update_{type}_scan_conversation: {e}",style="bold red")
            if isinstance(e,HTTPException):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in updating conversation , please try again later")
    
    @app.get("/{type}/conversation/{conversation_id}/export",summary="Export the results of a scan conversation")
    async def export_scan_conversation(type: scan_types, conversation_id: int, Authorization: Annotated[str | None, Header()] = None , dependencies=[Depends(limiter)] ):
        """
        Export the results of a scan conversation.
        """
        try:
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            # user = User(id=1) # for testing purposes
            Table = get_Table_from_type(type)
            
            scan_data = None
            
            # STEP [ 1 ] : ======================= Get the conversation from main db and check if export_results is already populated ========================================
            conversation = None
            with Session(engine) as session:
                conversation = session.exec(select(Table).where(Table.id == conversation_id).where(Table.user_id == user.id)).first()
                if not conversation:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Conversation not found")
                if conversation.scan_status not in ["success"]:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan has not completed yet or failed, cannot export results")
                if conversation.scan_data:
                    scan_data = conversation.scan_data

            
            
            # STEP [ 2 ] : =========================== create a temp pdf file to create the exported scan data pdf ========================================
            temp_pdf_file = tempfile.NamedTemporaryFile(suffix=".pdf",mode="w+",delete=False)
            temp_pdf_file.close()
            if type == "sast":
                generate_sast_pdf(scan_data, temp_pdf_file.name)
            elif type == "llm":
                generate_llm_pdf(scan_data, temp_pdf_file.name)
            elif type == "mcp":
                generate_mcp_pdf(scan_data, temp_pdf_file.name)
            elif type == "iac":
                generate_iac_pdf(scan_data, temp_pdf_file.name)
            elif type == "leakage":
                generate_gitleaks_pdf(scan_data, temp_pdf_file.name)
            elif type == "sbom_sca":
                generate_sbom_sca_pdf(scan_data, temp_pdf_file.name)
            elif type == "agent_discovery":
                generate_agent_discovery_pdf(scan_data, temp_pdf_file.name)
            else:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Export results not found")


            # STEP [ 4 ] : =========================== return the pdf file as a response ========================================
            return FileResponse(temp_pdf_file.name, media_type="application/pdf")
        
        except Exception as e:
            console.print(f"Error in export_{type}_scan_conversation: {e}",style="bold red")
            if isinstance(e,HTTPException) or isinstance(e,FileNotFoundError):
                raise e
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in exporting conversation , please try again later")
        finally:
            temp_pdf_file.close()
