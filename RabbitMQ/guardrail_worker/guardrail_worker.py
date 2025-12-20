from typing import Literal
from celery import Celery
from rich.console import Console
from dotenv import load_dotenv
import os
import sys
import json
from context import GuardrailContext
from guardrail_runner import run_guardrail
#====================================== Setting credentials to connect to broker ================================================================
try:
    load_dotenv()
    username = os.getenv("RABBIT_ADMIN_USERNAME")
    password = os.getenv("RABBIT_ADMIN_PASSWORD")
    mongo_url = os.getenv("RABBIT_MONGO_CONNECTION_URL")
    if not username or not password : 
        raise Exception()
except Exception as e :
    Console().print("Set username and password env variables to access broker",style="bold red")
    sys.exit()





#============================================================== Registering tasks to worker ==================================================================== 

try:
    # app = Celery('worker', broker=f"amqp://{username}:{password}@localhost:5672",backend='rpc://')
    app = Celery('guardrail_worker', broker=f"amqp://{username}:{password}@localhost:5672",backend=mongo_url)
    app.conf.update(
        RESULT_PERSISTENT=True,
        TASK_TRACK_STARTED=True,
    )
    Console().print(f"Celery App instantiated",style="bold green")


    
    @app.task(track_started=True)
    def input_guardrail(
        input_prompt: str,
        context : dict 
        ):
        """
        Expected context format : 
        {
            "input_prompt": "The input prompt to be scanned",
            "context": {
                "anonymize_context": { "preamble": "", "hidden_names": [], "threshold": 0.1, "allowed_names": [] },
                "toxicity_context": { "threshold": 0.1 },
                "tokenlimit_context": { "max_tokens": 2000 },
                "promptinjection_context": { "threshold": 0.1 },
                "regex_context": { "regex_patterns": [], "redact": False },
                "code_context": { "languages": [], "is_blocked": True },
                "secrets_context": { "redact_mode": "REDACT_PARTIAL" }
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
        return results
    Console().print(f"Registered Input guardrail task",style="bold green")


except Exception as e:
    Console().print(f"Error occured while registering tasks : {str(e)}",style="bold red")