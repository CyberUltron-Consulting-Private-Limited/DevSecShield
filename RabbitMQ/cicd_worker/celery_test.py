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



# simple_app = Celery('testing_tasks',
#                     broker=f"amqp://{username}:{password}@localhost:5672",
#                     backend='rpc://')
simple_app = Celery('testing_tasks',
                    broker=f"amqp://{username}:{password}@localhost:5672",
                    backend=mongo_url)


def test(
    task_name:str,
    kwargs:dict,
    result_file_name:str,
    scan_type:str = "sast",
     ):

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
            if status.state == "SUCCESS" or status.state == "FAILURE" :
                results = simple_app.AsyncResult(r.id).result
                Console().print(f"{task_name} completed",style="bold green")
                # results = parse_scan_results(results, scan_type=scan_type)
                # for testing
                with open(result_file_name, "w+") as f:
                    json.dump(results , f, indent=2)
                stop = True

       
    except Exception as e:
        Console().print(f"Error while testing:{str(e)}",style="bold red")



#------------------------------------------ testing SAST , ✅ Tested and works with context pattern ✅ ---------------------------------------------------------------------------
sast_kwargs = {
    "bucket_name":"devsecshield-storage",
    "object_name":"file-20251223192813920623-9c7a7231.zip",
    "app_lang":"python",
}
test(task_name="cicd_worker.sast",kwargs=sast_kwargs,result_file_name="zip_sast_results_testing.json",scan_type="sast")


