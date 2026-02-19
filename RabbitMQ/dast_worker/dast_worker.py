import json
from celery import Celery
from rich.console import Console
import time 
from dotenv import load_dotenv
import os
import sys
from helpers.base_vuln import parse_vuln_list
from helpers.progress_writer import StateUpdateWriter
from helpers.agent.dast_agent import DASTAgent
from helpers.agent.context import StartDASTScanData

console = Console()

# os.environ["IS_DOCKER_CONTAINER"] = "True"  # ⚠️⚠️⚠️⚠️⚠️⚠️⚠️

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
    app = Celery('worker', broker=broker_url,backend=mongo_url)
    app.conf.update(
        RESULT_PERSISTENT=True,
        TASK_TRACK_STARTED=True,
    )
    console.print(f"Celery App instantiated",style="bold green")


    
    @app.task(track_started=True , bind=True)
    def dast(
        self,
        dast_dict_context: dict,
        ):
        try :

            with open("mock_data.json", "r") as f:
                mock_data = json.load(f)
                return mock_data

            # start_time = time.time()
            
            # # STEP [ 1 ] : =========== Validate the context ======================
            # dast_context = StartDASTScanData.model_validate_json(json.dumps(dast_dict_context))

            # console.print(f"DAST context: {dast_context}",style="bold green")
            
            # progress_writer = StateUpdateWriter(self)

            # dast_agent = DASTAgent(
            #     dast_context=dast_context,
            #     state_update_writer=progress_writer,
            # )

            # vulnerabilities, metadata = dast_agent.run()
            # parsed_vulnerabilities = parse_vuln_list(vulnerabilities)
            # end_time = time.time()
            # duration_of_scan = end_time - start_time
            # return {
            #     "results": parsed_vulnerabilities,
            #     "metadata": metadata,
            #     "duration_of_scan": duration_of_scan,
            # }

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
            return 0.02
            
            # # STEP [ 1 ] : =========== Validate the context ======================
            # dast_context = StartDASTScanData.model_validate_json(json.dumps(dast_dict_context))

            # console.print(f"DAST context: {dast_context}",style="bold green")
            
            # dast_agent = DASTAgent(
            #     dast_context=dast_context,
            # )

            # return dast_agent.estimate_credits()

        except Exception as e:
            console.print(f"Error in dast estimation task: {str(e)}",style="bold red")
            raise e
        

    console.print(f"Registered DAST estimation task",style="bold green")


except Exception as e:
    console.print(f"Error in registering tasks: {e}",style="bold red")
    sys.exit()