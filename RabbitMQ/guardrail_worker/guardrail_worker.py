"""DEPRECATED: Guardrails Celery worker entrypoint.

Worker remains for legacy public API scans. Guardrails is removed from the
user-facing product UI — do not add new product workflows here.
"""

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

#====================================== Setting credentials to connect to broker ================================================================
try:
    load_dotenv()
    is_docker_container = os.getenv("IS_DOCKER_CONTAINER", "False") == "True"
    
    RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "devsecshield-rabbitmq" if is_docker_container else "localhost")
    RABBITMQ_PORT = os.getenv("RABBITMQ_PORT", "5672" if is_docker_container else "4672")
    MONGO_HOST = os.getenv("MONGO_HOST", "devsecshield-mongodb" if is_docker_container else "localhost")
    MONGO_PORT = os.getenv("MONGO_PORT", "27017")

    env_label = "Docker" if is_docker_container else "Local"
    console.print(f"{env_label} environment detected", style="bold green")

    # broker url
    username = os.getenv("RABBIT_ADMIN_USERNAME")
    password = os.getenv("RABBIT_ADMIN_PASSWORD")
    if not username or not password:
        raise Exception("RABBIT_ADMIN_USERNAME or RABBIT_ADMIN_PASSWORD not set")
    broker_url = f"amqp://{username}:{password}@{RABBITMQ_HOST}:{RABBITMQ_PORT}"

    # mongo url
    mongo_url = os.getenv("RABBIT_MONGO_CONNECTION_URL")
    if not mongo_url:
        mongo_username = os.getenv("MONGO_INITDB_ROOT_USERNAME")
        mongo_password = os.getenv("MONGO_INITDB_ROOT_PASSWORD")
        if mongo_username and mongo_password:
            mongo_url = f"mongodb://{mongo_username}:{mongo_password}@{MONGO_HOST}:{MONGO_PORT}/"
        else:
            mongo_url = f"mongodb://{MONGO_HOST}:{MONGO_PORT}/"

    console.print(f"Broker URL: {RABBITMQ_HOST}:{RABBITMQ_PORT}", style="bold green")
    console.print(f"Mongo URL: {MONGO_HOST}:{MONGO_PORT}", style="bold green")
    # SECURITY: Credentials masked - never log sensitive connection strings
    
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
        # SECURITY: Global task timeout defaults to prevent unbounded execution
        task_time_limit=300,           # Hard kill after 5 minutes
        task_soft_time_limit=240,      # SoftTimeLimitExceeded after 4 minutes
        task_acks_late=True,           # Re-queue if worker dies
        task_reject_on_worker_lost=True,
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