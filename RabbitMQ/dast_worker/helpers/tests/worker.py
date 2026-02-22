from dis import disco
import json
from celery import Celery
from celery.result import AsyncResult
import time 
from rich.console import Console
from dotenv import load_dotenv
load_dotenv()
import os
from rich.console import Console
console = Console()
try:
    load_dotenv()
    username = os.getenv("RABBIT_ADMIN_USERNAME")
    password = os.getenv("RABBIT_ADMIN_PASSWORD")
    mongo_url = os.getenv("RABBIT_MONGO_CONNECTION_URL")
except Exception as e :
    console.print("Set username and password env variables to access broker",style="bold red")



# simple_app = Celery('testing_tasks',
#                     broker=f"amqp://{username}:{password}@localhost:5672",
#                     backend='rpc://')
simple_app = Celery('testing_tasks',
                    broker=f"amqp://{username}:{password}@localhost:4672",
                    backend=mongo_url)


def test(
    task_name:str,
    kwargs:dict,
    result_file_name:str | None = None,
     ):

    try:
       
        r = simple_app.send_task(task_name, kwargs=kwargs , queue="dast_worker_queue")
        simple_app.conf.update(
        CELERY_RESULT_PERSISTENT=True,
        CELERY_TRACK_STARTED=True,
        )
        console.print(f"{task_name} Task initiated",style="dim blue1")
        stop = False 

        while not stop:
            status : AsyncResult = simple_app.AsyncResult(r.id, app=simple_app)
            time.sleep(2)
            console.print(f"Status : {status.state}",style="dim yellow")
            if status.state == "STARTED":
                console.print(f"Task {task_name} started",style="bold yellow1")
                console.print(f"STARTED task state metadata : {status.info}",style="bold yellow1")
            if status.state == "SUCCESS" or status.state == "FAILURE" :
                results = simple_app.AsyncResult(r.id).result
                console.print(f"{task_name} completed",style="bold green")
                if status.state == "SUCCESS" and result_file_name:
                    with open(result_file_name, "w+") as f:
                        json.dump(results , f, indent=2)

                if not result_file_name:
                    console.print(f"Results: {results}",style="bold orange1")
                stop = True

       
    except Exception as e:
        console.print(f"Error while testing:{str(e)}",style="bold red")



# ------------------------------------------- testing DAST ---------------------------------------------------------------------------
xpath_of_username_field = "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[1]/td[2]/input"
xpath_of_password_field = "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[2]/td[2]/input"
username = "jsmith"
password = "demo123"
xpath_of_submit_button = "/html/body/table/tbody/tr[2]/td[2]/div/form/table/tbody/tr[3]/td[2]/input"

auth = {
    "login_url": "https://demo.testfire.net/login.jsp",
    "xpath_of_username_field": xpath_of_username_field,
    "xpath_of_password_field": xpath_of_password_field,
    "username": username,
    "password": password,
    "xpath_of_submit_button": xpath_of_submit_button
}
dast_dict_context = {
    "target_url": "https://demo.testfire.net/index.jsp",
    "auth": auth,
    "scan_speed": "fast",
    "max_urls": 1,
    "additional_urls_to_scan": [],
    "exclude_url_patterns": [],
    "include_url_patterns": []
}

dast_kwargs = {
    "dast_dict_context": dast_dict_context
}
test(task_name="dast_worker.dast",kwargs=dast_kwargs,result_file_name="dast_results_testing.json")

# test(task_name="dast_worker.dast_estimation",kwargs=dast_kwargs,result_file_name="dast_results_testing.json")
