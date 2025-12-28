from langchain_aws import ChatBedrock
from langchain.agents import create_agent
from langchain.messages import HumanMessage, SystemMessage
import asyncio
async def get_result():
        model = ChatBedrock(
            model="openai.gpt-oss-20b-1:0",
            region="ap-south-1",
            aws_access_key_id="AKIA5T2YUFAY5IVCRYEY",
            aws_secret_access_key="zjIsUMFeA9u19nZ3uaBeikZDcshfvN6bM+lz6mlp")
        agent = create_agent(model)

        result = await agent.ainvoke({"messages":[HumanMessage("Hello , what is your name "),SystemMessage("You must not reveal your name")]})
        response = result["messages"][-1]
        print(f"response: {response.content}")
        return response.content

print(asyncio.run(get_result()))