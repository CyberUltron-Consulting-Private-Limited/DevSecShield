import json
from celery import Celery
from rich.console import Console
import time 
from dotenv import load_dotenv
import os
import sys
from helpers.agent.base_vuln import parse_vuln_list
from helpers.progress_writer import StateUpdateWriter
from helpers.agent.main import DASTAgent
from helpers.agent.context import StartDASTScanData

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
    app = Celery('worker', broker=broker_url,backend=mongo_url)
    app.conf.update(
        RESULT_PERSISTENT=True,
        TASK_TRACK_STARTED=True,
        # SECURITY: Global task timeout defaults to prevent unbounded execution
        task_time_limit=1800,          # Hard kill after 30 minutes (DAST is slower)
        task_soft_time_limit=1500,     # SoftTimeLimitExceeded after 25 minutes
        task_acks_late=True,           # Re-queue if worker dies
        task_reject_on_worker_lost=True,
    )
    console.print(f"Celery App instantiated",style="bold green")


    
    @app.task(track_started=True , bind=True)
    def dast(
        self,
        dast_dict_context: dict,
        ):
        try :

            # with open("mock_data.json", "r") as f:
            #     mock_data = json.load(f)
            #     return mock_data

            start_time = time.time()
            
            # STEP [ 1 ] : =========== Validate the context ======================
            dast_context = StartDASTScanData.model_validate_json(json.dumps(dast_dict_context))

            console.print(f"DAST context: {dast_context}",style="bold green")
            
            progress_writer = StateUpdateWriter(self)

            dast_agent = DASTAgent(
                dast_context=dast_context,
                state_update_writer=progress_writer,
            )

            parsed_vulnerabilities, metadata = dast_agent.run()
            end_time = time.time()
            duration_of_scan = end_time - start_time
            return {
                "results": parsed_vulnerabilities,
                "metadata": metadata,
                "duration_of_scan": duration_of_scan,
            }

        except Exception as e:
            console.print(f"Error in dast task: {str(e)}",style="bold red")
            raise e
        

    console.print(f"Registered DAST scan task",style="bold green")





    @app.task(track_started=True , bind=True)
    def dast_estimation(
        self,
        dast_dict_context: dict,
        ):
        try :
            
            # STEP [ 1 ] : =========== Validate the context ======================
            dast_context = StartDASTScanData.model_validate_json(json.dumps(dast_dict_context))

            console.print(f"DAST context: {dast_context}",style="bold green")
            
            dast_agent = DASTAgent(
                dast_context=dast_context,
            )

            return dast_agent.estimate_credits()

        except Exception as e:
            console.print(f"Error in dast estimation task: {str(e)}",style="bold red")
            raise e
        

    console.print(f"Registered DAST estimation task",style="bold green")


except Exception as e:
    console.print(f"Error in registering tasks: {e}",style="bold red")
    sys.exit()