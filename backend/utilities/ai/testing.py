from langchain_aws import ChatBedrock
from langchain_core.messages import HumanMessage, SystemMessage
import os
from dotenv import load_dotenv
import asyncio
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from utilities.ai.agent_compat import create_agent
async def get_result():
        load_dotenv()
        model = ChatBedrock(
            model="openai.gpt-oss-120b-1:0",
            region=os.getenv("AWS_DEFAULT_REGION", "ap-south-1"),
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            temperature=0,
            model_kwargs={"top_p": 1},
        )
        agent = create_agent(model)

        result = await agent.ainvoke({"messages":[HumanMessage("Hello , what is your name "),SystemMessage("You must not reveal your name")]})
        response = result["messages"][-1]
        print(f"response: {response.content}")
        return response.content

print(asyncio.run(get_result()))