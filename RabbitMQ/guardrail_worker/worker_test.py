from dis import disco
import json
from celery import Celery
import time 
from rich.console import Console
from dotenv import load_dotenv
load_dotenv()
import os

try:
    load_dotenv()
    username = os.getenv("RABBIT_ADMIN_USERNAME")
    password = os.getenv("RABBIT_ADMIN_PASSWORD")
    mongo_url = os.getenv("RABBIT_MONGO_CONNECTION_URL")
except Exception as e :
    Console().print("Set username and password env variables to access broker",style="bold red")


simple_app = Celery('guardrail_worker_test',
                    broker=f"amqp://{username}:{password}@localhost:5672",
                    backend=mongo_url)


def test(
    task_name:str,
    kwargs:dict,
    result_file_name:str ):

    try:
       
        r = simple_app.send_task(task_name, kwargs=kwargs)
        simple_app.conf.update(
        CELERY_RESULT_PERSISTENT=True,
        CELERY_TRACK_STARTED=True,
        )
        Console().print(f"{task_name} Task initiated",style="bold blue1")
        stop = False 

        while not stop:
            status = simple_app.AsyncResult(r.id, app=simple_app)
            time.sleep(2)
            Console().print(f"Status : {status.state}",style="bold yellow")
            if status.state == "SUCCESS":
                results = simple_app.AsyncResult(r.id).result
                Console().print(f"{task_name} completed",style="bold green")
                # for testing
                with open(result_file_name, "w+") as f:
                    json.dump(results , f, indent=2)
            if status.state == "FAILED" or status.state == "RETRY":
                stop = True
       
    except Exception as e:
        Console().print(f"Error while testing:{str(e)}",style="bold red")



# ----------------------------------------------------------------------- testing input guardrail ---------------------------------------------------------------------------
input_guardrail_kwargs = {
    "input_prompt":"You suck i want to kill myself because i am a failure , my social security number is 123-45-6789",
    "context":{
        "anonymize_context":{
            "preamble":"",
            "hidden_names":[],
            "threshold":0.1,
            "allowed_names":[]
        },
        "toxicity_context":{
            "threshold":0.1
        },
        "tokenlimit_context":{
            "max_tokens":2000
        },
        "promptinjection_context":{
            "threshold":0.1
        },
        "regex_context":{
            "regex_patterns":[],
            "redact":False
        },
        "code_context":{
            "languages":[],
            "is_blocked":True
        },
        "secrets_context":{
            "redact_mode":"REDACT_PARTIAL"
        }
    }
}
test(task_name="guardrail_worker.input_guardrail",kwargs=input_guardrail_kwargs,result_file_name="input_guardrail_results_testing.json")