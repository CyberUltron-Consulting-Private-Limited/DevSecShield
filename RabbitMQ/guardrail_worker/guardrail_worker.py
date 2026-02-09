from typing import Literal
from celery import Celery
from rich.console import Console
from dotenv import load_dotenv
import os
import sys
import json
from context import GuardrailContext
from context import TicketingIntegrationContext
from guardrail_runner import run_guardrail
from ticketing.main import create_issue_in_for_results

console = Console()

# os.environ["IS_DOCKER_CONTAINER"] = "False"  # ⚠️⚠️⚠️⚠️⚠️⚠️⚠️

#====================================== Setting credentials to connect to broker ================================================================
try:
    load_dotenv()
    is_docker_container = os.getenv("IS_DOCKER_CONTAINER")
    if is_docker_container and is_docker_container == "True":
        console.print(f"Docker container detected",style="bold green")

        #broker url
        username = os.getenv("RABBIT_ADMIN_USERNAME")
        password = os.getenv("RABBIT_ADMIN_PASSWORD")
        broker_url = f"amqp://{username}:{password}@13.203.233.15:4672"

        #mongo url
        mongo_username = os.getenv("MONGO_INITDB_ROOT_USERNAME")
        mongo_password = os.getenv("MONGO_INITDB_ROOT_PASSWORD")
        mongo_host = "13.203.233.15"
        mongo_port = "27017"
        mongo_url = f"mongodb://{mongo_username}:{mongo_password}@{mongo_host}:{mongo_port}/"

        #check if credentials are set
        if not username or not password  or not mongo_username or not mongo_password: 
            raise Exception("Username, password or mongo username or password not set")
        
        console.print(f"Broker URL: {broker_url}",style="bold green")
        console.print(f"Mongo URL: {mongo_url}",style="bold green")
    else:
        console.print(f"Local container detected",style="bold green")

        #broker url
        username = os.getenv("RABBIT_ADMIN_USERNAME")
        password = os.getenv("RABBIT_ADMIN_PASSWORD")
        broker_url = f"amqp://{username}:{password}@localhost:4672"

        #mongo url
        mongo_url = os.getenv("RABBIT_MONGO_CONNECTION_URL")
        if not username or not password or not mongo_url: 
            raise Exception("Username, password or mongo url not set")
        
        #check if credentials are set
        if not username or not password or not mongo_url: 
            raise Exception("Username, password or mongo url not set")
        
        console.print(f"Broker URL: {broker_url}",style="bold green")
        console.print(f"Mongo URL: {mongo_url}",style="bold green")
    
except Exception as e :
    console.print(f"Error in getting credentials: {e}",style="dim red")
    sys.exit()
#============================================================== Registering tasks to worker ==================================================================== 

try:
    # app = Celery('worker', broker=f"amqp://{username}:{password}@localhost:5672",backend='rpc://')
    app = Celery('guardrail_worker', broker=broker_url,backend=mongo_url)
    app.conf.update(
        RESULT_PERSISTENT=True,
        TASK_TRACK_STARTED=True,
    )
    Console().print(f"Celery App instantiated",style="bold green")


    
    @app.task(track_started=True)
    def input_guardrail(
        input_prompt: str,
        context : dict ,
        ticketing_integration_context : dict | None = None ,
        ):
        """
        Expected context format : 
        {
            "input_prompt": "The input prompt to be scanned",
            "context": {
                "anonymize_context": { "preamble": "", "threshold": 0.1, "allowed_names": [] },
                "toxicity_context": { "threshold": 0.1 },
                "tokenlimit_context": { "max_tokens": 2000 },
                "promptinjection_context": { "threshold": 0.1 },
                "regex_context": { "regex_patterns": [], "redact": False },
                "code_context": { "languages": [], "is_blocked": True },
                "secrets_context": { "redact_mode": "REDACT_PARTIAL" }
            }
            "ticketing_integration_context": {
                "jira": {
                    "jira_project_id": "1234567890"
                    "jira_api_token": "1234567890"
                    "jira_url": "https://your-jira-instance.atlassian.net"
                    "jira_email": "your-jira-email@example.com"
                }
            }
        }
        
        set scanner context to None if the scanner is not enabled 
        {
            "anonymize_context": None,
        }
        """
        
        json_context = json.dumps(context)
        context = GuardrailContext.model_validate_json(json_context)
        print(context)

        results = run_guardrail(
            input_prompt=input_prompt,
            context=context,
        )

        try:
            if ticketing_integration_context:
                print(ticketing_integration_context)
                # if ticketing integration context is provided , then validate it
                json_ticketing_integration_context = json.dumps(ticketing_integration_context)
                ticketing_integration_context_model = TicketingIntegrationContext.model_validate_json(json_ticketing_integration_context)
                print(ticketing_integration_context_model)

                # create issue with ticketing integration context 
                create_issue_in_for_results(
                    input_prompt=input_prompt, 
                    results=results, 
                    ticketing_integration_context=ticketing_integration_context_model)
        except Exception as e:
            console.print(f"Error in creating issue in ticketing integration: {str(e)}",style="dim red")
            pass
            
        return results
    Console().print(f"Registered Input guardrail task",style="bold green")


except Exception as e:
    Console().print(f"Error occured while registering tasks : {str(e)}",style="bold red")