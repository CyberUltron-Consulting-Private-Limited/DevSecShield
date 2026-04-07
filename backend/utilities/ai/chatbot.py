import asyncio
import datetime
from email import message
import json
from typing import Literal
from bson import ObjectId
from fastapi import HTTPException, status
from langchain_aws import ChatBedrock
from langchain_core.messages import AnyMessage, HumanMessage , SystemMessage , AIMessage
from pymongo.database import Database
from rich.console import Console
from dotenv import load_dotenv
import os
from backend.utilities.ai.llm import get_llm
from backend.utilities.ai.agent_compat import create_agent

from backend.mongo_models import ActiveContextLog, MessageLog

console = Console()

load_dotenv()
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_DEFAULT_REGION")
if not AWS_ACCESS_KEY_ID or not AWS_SECRET_ACCESS_KEY or not AWS_REGION:
    raise Exception("AWS credentials not found")
else: 
    console.print(f"AWS credentials found",style="bold green")

def add_message(messages:list[AnyMessage],role:Literal["human" , "system" , "ai"]=None,content:str=None ):
    
    try:

        if not content or role not in ["human","system","ai"] :
            raise Exception("Inputs missing")
        
        message = None 
        if role=="human":
            message = HumanMessage(content)
        elif role=="ai":
            message = AIMessage(content)
        elif role=="system":
            message = SystemMessage(content)

        if message:
            messages.append(message)
            Console().print(f"Added message from {role} to chat history of length {len(messages)-1}",style="bold green")
            return messages 
        else:
            raise Exception("Message failed to add")
    except Exception as e:
        Console().print(f"Error Occured while adding message : {e}",style="bold red")





async def chatbot_response(
    scan_type:Literal["SAST" , "SCA+SBOM" , "IAC" , "Code/Data Leakage" , "MCP Server" , "LLM Benchmarking" , "AI Agent Discovery"],
    scan_results:str,
    history:list[AnyMessage],
    content:str,
    role:Literal["human" ,"system" ,"ai"],
    ):
    """
    This function's only purpose is to generate a response to a user message . 
    The scan results context lingers for every response as a system prompt
    """

    load_dotenv()
    system_prompt = f"""
    You are a Cybersecurity Expert who has just run a {scan_type} scan . Keeping the results of the scan in mind , answer any question the user asks. ( Sidenote : Do not generate a Markdown response , the response can at most use bullets and numbering )
    ## Scan Results :
    {scan_results} 
    """
    model = get_llm()
    agent = create_agent(model,system_prompt=system_prompt)
    new_history = add_message(messages=history, role=role , content=content)


    result = await agent.ainvoke({"messages":new_history})
    response = result["messages"][-1]
    response_string = response.content

    start = response_string.find("<reasoning>")
    end = response_string.find("</reasoning>")
    reasoning = response_string[start:end+len("</reasoning>")].replace("<reasoning>", "").replace("</reasoning>", "")
    content_without_reasoning = response_string[:start] + response_string[end+len("</reasoning>"):]
    
    return {
        "content" : content_without_reasoning , 
        "reasoning" : reasoning 
    }
    


    # old streaming mode ( throws a lot of errors )
    # for token, metadata in agent.stream(  
    #     {"messages": new_history },
    #     stream_mode="messages",
    # ):
    #     # print(f"metadata: {metadata}")
    #     # print(f"token: {token}")

    #     # print(f"token.content_blocks: {len(token.content_blocks)}")
    #     for content_block in token.content_blocks:
    #         content = content_block["text"]
    #         start = content.find("<reasoning>")
    #         end = content.find("</reasoning>")
    #         reasoning = content[start:end+len("</reasoning>")].replace("<reasoning>", "").replace("</reasoning>", "")
    #         content_without_reasoning = content[:start] + content[end+len("</reasoning>"):]
    #         data = {
    #             # "mongo_message_id": mongo_message_id, # this message id is useless ( the UI employs an auto incrementing integer for message id )
    #             "content": content_without_reasoning,
    #             "reasoning": reasoning,
    #         }
    #         Console().print(f"yielding data: {data}",style="bold green")
    #         yield(json.dumps(data))




def summarize ( history : list[AnyMessage] ):
    model = get_llm()
    summarizing_agent = create_agent(model,system_prompt="You are a summarizing agent, please summarize the chat history given to you and output the results to the user")
    result = summarizing_agent.invoke({"messages":history})
    summarized_history = result["messages"][-1]
    return summarized_history.content


async def create_response(
    scan_id:int,
    mongo_db: Database,
    scan_type:Literal["SAST" , "SCA+SBOM" , "IAC" , "Code/Data Leakage" , "MCP Server" , "LLM Benchmarking" , "AI Agent Discovery"],
    scan_results:str,
    content:str,
    role:Literal["human" ,"system" ,"ai"],
    max_history_length:int=3 ):

    """
    Args :
    - scan_id : scan id
    - mongo_db : mongo db instance
    - scan_type : scan type
    - scan_results : scan results
    - content : new user message
    - role : role of the new user message
    - max_history_length : max history length

    Prerequisites : 
    1. new user message has already been added to message log collection , before calling this function
    2. new user message has already been added to the active context collection , before calling this function
    

    Note : 
    the chatbot_response function is responsible only responsible for streaming/yielding the response text stream , given the chat history and new user message
    """
    
    try:
        
        # STEP [ 1 ] ========================= Get active context history from the database ===============================================
        
        active_context_collection = mongo_db["active_context"]
        history = []
        for item in active_context_collection.find({"scan_id":scan_id}):
            Message = None
            if item["sender"] == "user":
                Message = HumanMessage(item["content"])
            elif item["sender"] == "assistant":
                Message = AIMessage(item["content"])
            history.append(Message)
        console.print(f"Active context history of length {len(history)} found for scan {scan_id}",style="bold green")


        
        
        # STEP [ 2 ] ========================= Summarize the chat history when active history is above limit ===============================================
        if len(history) >= max_history_length:
            Console().print(f"Chat history has reached its maximum length of {max_history_length}. Summarizing chat...",style="dim orange1")
            
            # STEP [ 2a ] -----------------> summarize 
            summarized_history = summarize(history=history)

            # STEP [ 2b ] ----------------> delete all active context items for the conversation
            active_context_collection = mongo_db["active_context"]
            for item in active_context_collection.find({"scan_id":scan_id}):
                active_context_collection.delete_one({"_id":item["_id"]})
            console.print(f"Deleted all active context items for scan {scan_id} , replacing with summarized history",style="bold blue")
            
            # STEP [ 2c ] ----------------> add the summarized history to the active context collection
            active_context_instance = ActiveContextLog(
                scan_id=scan_id,
                content=summarized_history,
                type="message",
                sender="assistant",
                created_at=datetime.datetime.now(datetime.timezone.utc),
            )
            result = active_context_collection.insert_one(active_context_instance)
            console.print(f"Summarized history added to active context collection for scan {scan_id} with _id {str(result.inserted_id)}",style="bold green")
            
            # STEP [ 4 ] ----------------> update the lanchain history with the summarized history
            history=[AIMessage(summarized_history)]
            Console().print(f"Chat history summarized ✔️",style="bold green")





        # STEP [ 3 ] ======================================== Generate Response =========================================================================================
        
        console.print(f"Content being sent to chatbot_response : {content}",style="dim orange1")
        chatbot_response_data = await chatbot_response(
            scan_results=scan_results,
            scan_type=scan_type,
            history=history,
            content=content,
            role=role, )
        assistant_generated_response = chatbot_response_data["content"]






        # STEP [ 4 ] ============================ Add assistant message to the message log collection and active context collection ============================ ⭐
        
        # STEP [ 4a ] ----------------> adding message to the message log collection
        messages_collection = mongo_db["message_log"]
        message_instance = MessageLog(
            scan_id=scan_id,
            content=assistant_generated_response,
            type="message",
            sender="assistant",
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
        assistant_message_result = messages_collection.insert_one(message_instance)
        console.print(f"Assistant message added to message log collection for scan {scan_id} with _id {str(assistant_message_result.inserted_id)}",style="bold green")

        # STEP [ 4b ] ----------------> adding message to the active context collection
        active_context_collection = mongo_db["active_context"]
        active_context_instance = ActiveContextLog(
            scan_id=scan_id,
            content=assistant_generated_response,
            type="message",
            sender="assistant",
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
        assistant_active_context_result = active_context_collection.insert_one(active_context_instance)
        console.print(f"Assistant message added to active context collection for scan {scan_id} with _id {str(assistant_active_context_result.inserted_id)}",style="bold green")

        
        return chatbot_response_data
        

    except Exception as e:
        Console().print(f"An error has occured : {str(e)}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR , detail="Could not generate response , try again later")
    
   
        