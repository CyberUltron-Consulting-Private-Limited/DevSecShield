from email import message
from typing import Literal
from fastapi import HTTPException, status
from langchain.agents import create_agent
from langchain_aws import ChatBedrock
from langchain.messages import AnyMessage, HumanMessage , SystemMessage , AIMessage
from rich.console import Console
from dotenv import load_dotenv

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





def chatbot_response(
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
    You are a Cybersecurity Expert who has just run a {scan_type} scan . Keeping the results of the scan in mind , answer any question the user asks.
    ## Scan Results :
    {scan_results} 
    """
    model = ChatBedrock(
        model="openai.gpt-oss-20b-1:0",
        region="ap-south-1",
        aws_access_key_id="AKIA5T2YUFAY5IVCRYEY",
        aws_secret_access_key="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")

    agent = create_agent(model,system_prompt=system_prompt)

    
    new_history = add_message(messages=history, role=role , content=content)


    for token, metadata in agent.stream(  
        {"messages": new_history },
        stream_mode="messages",
    ):
        yield(f"node: {metadata['langgraph_node']}  content: {token.content_blocks}\n")




def summarize ( history : list[AnyMessage] ):
    model = ChatBedrock(
        model="openai.gpt-oss-20b-1:0",
        region="ap-south-1",
        aws_access_key_id="AKIA5T2YUFAY5IVCRYEY",
        aws_secret_access_key="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")
    summarizing_agent = create_agent(model,system_prompt="You are a summarizing agent, please summarize the chat history given to you and output the results to the user")
    result = summarizing_agent.invoke({"messages":history})
    summarized_history = result["messages"][-1]
    return summarized_history


def create_response(
    scan_type:Literal["SAST" , "SCA+SBOM" , "IAC" , "Code/Data Leakage" , "MCP Server" , "LLM Benchmarking" , "AI Agent Discovery"],
    scan_results:str,
    content:str,
    role:Literal["human" ,"system" ,"ai"],
    max_history_length:int=3 ):

    """
    Handle all summarizing , db querying and saving here before invoking a response from the model
    
    TO DO : query and get active history inside this function instead of passing as args .  Only receive new message as args 
    """
    
    try:
        # STEP [ 1 ] ========================Add new message to messages log ==============================================================================
        
        # TO DO ⚠️

        # STEP [ 2 ] ========================= Summarize the chat history when active history is above limit ===============================================
        
        history = [] # empty history to be updated later with a query to the db 

        if len(history) >= max_history_length:
            Console().print(f"Chat history has reached its maximum length of {max_history_length}. Summarizing chat...",style="bold blue1")
            # STEP [ 1 ] -----------------> summarize
            summarized_history = summarize(history=history)
            # STEP [ 2 ] ----------------> update active context ( add the part where it updates mongo db active context )
            # TO DO ⚠️
            history=summarized_history

            Console().print(f"Chat history summarized ✔️",style="bold green")

        # STEP [ 3 ] ======================================== Generate Response =========================================================================================
        return chatbot_response(
        scan_results=scan_results,
            scan_type=scan_type,
            history=history,
            content=content,
            role=role, 
        )
    except Exception as e:
        Console().print(f"An error has occured : {str(e)}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR , detail="Could not generate response , try again later")

if __name__=="__main__":

    streamer = create_response(
        scan_results="API Key compromised",
        scan_type='SAST',
        content="hi",
        role="human",
    )
    # print(type(streamer["messages"][-1]))
    for stream in streamer:
        Console().print(stream,style="bold green")