from typing import Literal, Optional
from celery import Celery
from rich.console import Console
from celery.result import AsyncResult
import time 
from dotenv import load_dotenv
import os
import sys
from tools.sast_utils.zip_sast_runner import run_sast_scan
import json

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
    app = Celery('cicd_worker', broker=f"amqp://{username}:{password}@localhost:5672",backend=mongo_url)
    app.conf.update(
        RESULT_PERSISTENT=True,
        TASK_TRACK_STARTED=True,
    )
    Console().print(f"Celery App instantiated",style="bold green")


    # ------------------------------------------- SAST Scanning task -------------------------------------------------------------------------------------------
    """
    You can add track_started=True to the task decorator to track the start time of the task. i.e. "STARTED" state will be used to track the start time of the task.
    example : @app.task(track_started=True)

    If you are enabling this , then make sure the frontend polls even status is "started" , becase as of now it only polls when status is "pending".
    """
    
    @app.task(track_started=True)
    def sast(
        bucket_name: str, 
        object_name: str, 
        app_lang:Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"]):


        try :
            
            # STEP [ 2 ] : =========== Run the sast scan ======================
            results = run_sast_scan( bucket_name=bucket_name, object_name=object_name, app_lang=app_lang)  

            # STEP [ 3 ] : =========== Return the results ======================
            return results

        except Exception as e:
            Console().print(f"Error in sast task: {str(e)}",style="bold red")
            raise e
    Console().print(f"Registered SAST task",style="bold green")


except Exception as e:
    Console().print(f"Error in registering tasks: {str(e)}",style="bold red")
    sys.exit()
