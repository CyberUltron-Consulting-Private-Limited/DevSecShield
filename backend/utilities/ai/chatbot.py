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





SCAN_TYPE_DISPLAY_NAMES = {
    "sast": "SAST",
    "dast": "DAST",
    "sbom_sca": "SCA+SBOM",
    "iac": "IAC",
    "leakage": "Code/Data Leakage",
    "mcp": "MCP Server",
    "llm": "LLM Benchmarking",
    "agent_discovery": "AI Agent Discovery",
    "cbom": "CBOM (Cryptographic Bill of Materials)",
    "ai_bom": "AI-BOM (AI Bill of Materials)",
    "mobile": "Mobile App Security",
}


async def chatbot_response(
    scan_type:str,
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
    display_name = SCAN_TYPE_DISPLAY_NAMES.get(scan_type, scan_type)
    system_prompt = f"""
    You are a Cybersecurity Expert who has just run a {display_name} scan . Keeping the results of the scan in mind , answer any question the user asks. ( Sidenote : Do not generate a Markdown response , the response can at most use bullets and numbering )

    ## Grounding rules ( mandatory ) :
    1. Answer ONLY using the scan results provided below ( and any prior summary in this conversation that was derived from them ) . Do not rely on outside knowledge to assert that a specific finding, file, vulnerability, package, or identifier exists for this scan.
    2. Do NOT invent, fabricate, or guess findings, file paths, line numbers, CVE/CWE ids, package names, versions, or severities. Only state details that actually appear in the scan results.
    3. If the user asks about something that is not present in the scan results, say plainly that it is not in the scan results rather than inventing an answer. You may then offer general security guidance, but make it clear that it is general advice and not a finding from this scan.

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




SUMMARIZER_SYSTEM_PROMPT = (
    "You are a summarizing agent that compresses the OLDEST part of a chat history "
    "between a user and a cybersecurity assistant. Produce a concise summary that the "
    "assistant can use as background context for the rest of the conversation.\n"
    "GROUNDING RULES (mandatory):\n"
    "1. PRESERVE every concrete scan finding, identifier, file path, line number, CVE/CWE id, "
    "vulnerability name, package/version, severity, and any other specific fact VERBATIM. "
    "Do not generalize or drop these details.\n"
    "2. NEVER invent, infer, or embellish findings, identifiers, or details that are not "
    "explicitly present in the messages you are summarizing. If something was not stated, do not add it.\n"
    "3. It is better to quote a concrete finding exactly than to paraphrase it.\n"
    "Output only the summary."
)


def summarize ( history : list[AnyMessage] ):
    model = get_llm()
    summarizing_agent = create_agent(model,system_prompt=SUMMARIZER_SYSTEM_PROMPT)
    result = summarizing_agent.invoke({"messages":history})
    summarized_history = result["messages"][-1]
    return summarized_history.content


async def create_response(
    scan_id:int,
    mongo_db: Database,
    scan_type:str,
    scan_results:str,
    content:str,
    role:Literal["human" ,"system" ,"ai"],
    max_history_length:int=12,
    retained_raw_messages:int=6 ):

    """
    Args :
    - scan_id : scan id
    - mongo_db : mongo db instance
    - scan_type : scan type
    - scan_results : scan results
    - content : new user message
    - role : role of the new user message
    - max_history_length : number of raw active-context messages allowed before summarization kicks in
    - retained_raw_messages : number of most-recent raw messages kept verbatim (only the OLDER messages are summarized)

    Prerequisites : 
    1. new user message has already been added to message log collection , before calling this function
    2. new user message has already been added to the active context collection , before calling this function
    

    Note : 
    the chatbot_response function is responsible only responsible for streaming/yielding the response text stream , given the chat history and new user message
    """
    
    try:
        
        # STEP [ 1 ] ========================= Get active context history from the database ===============================================
        
        active_context_collection = mongo_db["active_context"]
        # Keep the raw documents (with _id / sender) in insertion order so we can later
        # summarize ONLY the oldest messages while retaining the most recent ones verbatim.
        raw_items = list(active_context_collection.find({"scan_id":scan_id}).sort("created_at", 1))
        history = []
        for item in raw_items:
            Message = None
            if item["sender"] == "user":
                Message = HumanMessage(item["content"])
            elif item["sender"] == "assistant":
                Message = AIMessage(item["content"])
            history.append(Message)
        console.print(f"Active context history of length {len(history)} found for scan {scan_id}",style="bold green")


        
        
        # STEP [ 2 ] ========================= Summarize the OLDEST chat history when active history is above limit ===============================================
        # Conservative strategy: only compress when we exceed max_history_length, and even then
        # summarize ONLY the oldest messages while RETAINING the most recent `retained_raw_messages`
        # turns verbatim. This avoids the previous behaviour of collapsing the entire conversation
        # into a single lossy message, which dropped concrete scan findings and led to fabrication.
        if len(history) > max_history_length:
            Console().print(f"Chat history has exceeded its maximum length of {max_history_length}. Summarizing oldest messages while keeping the last {retained_raw_messages} verbatim...",style="dim orange1")

            # Split into the oldest messages (to be summarized) and the most recent ones (kept raw).
            keep_count = min(retained_raw_messages, len(raw_items))
            old_items = raw_items[:len(raw_items) - keep_count]
            recent_items = raw_items[len(raw_items) - keep_count:]

            if old_items:
                old_history = history[:len(old_items)]
                recent_history = history[len(old_items):]

                # STEP [ 2a ] -----------------> summarize ONLY the oldest messages
                summarized_history = summarize(history=old_history)

                # STEP [ 2b ] ----------------> delete ONLY the oldest active context items
                active_context_collection = mongo_db["active_context"]
                for item in old_items:
                    active_context_collection.delete_one({"_id":item["_id"]})
                console.print(f"Deleted {len(old_items)} oldest active context items for scan {scan_id} , replacing with one summary (kept {len(recent_items)} recent messages verbatim)",style="bold blue")

                # STEP [ 2c ] ----------------> insert the summary as the OLDEST item so ordering is preserved
                # Use a created_at strictly before the oldest retained message so the summary
                # always sorts ahead of the retained raw turns on the next read.
                if recent_items:
                    summary_created_at = recent_items[0]["created_at"] - datetime.timedelta(microseconds=1)
                else:
                    summary_created_at = datetime.datetime.now(datetime.timezone.utc)
                active_context_instance = ActiveContextLog(
                    scan_id=scan_id,
                    content=summarized_history,
                    type="message",
                    sender="assistant",
                    created_at=summary_created_at,
                )
                result = active_context_collection.insert_one(active_context_instance)
                console.print(f"Summarized history added to active context collection for scan {scan_id} with _id {str(result.inserted_id)}",style="bold green")

                # STEP [ 2d ] ----------------> rebuild the in-memory history: summary first, then retained raw turns
                history=[AIMessage(summarized_history)] + recent_history
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
    
   
        