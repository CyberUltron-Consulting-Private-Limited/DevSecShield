from dis import disco
import json
from celery import Celery
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
                    broker=f"amqp://{username}:{password}@localhost:5672",
                    backend=mongo_url)


def test(
    task_name:str,
    kwargs:dict,
    result_file_name:str | None = None,
    scan_type:str = "sast",
     ):

    try:
       
        r = simple_app.send_task(task_name, kwargs=kwargs , queue="scan_worker_queue")
        simple_app.conf.update(
        CELERY_RESULT_PERSISTENT=True,
        CELERY_TRACK_STARTED=True,
        )
        console.print(f"{task_name} Task initiated",style="dim blue1")
        stop = False 

        while not stop:
            status = simple_app.AsyncResult(r.id, app=simple_app)
            time.sleep(2)
            console.print(f"Status : {status.state}",style="dim yellow")
            if status.state == "SUCCESS" or status.state == "FAILURE" :
                results = simple_app.AsyncResult(r.id).result
                console.print(f"{task_name} completed",style="bold green")
                # results = parse_scan_results(results, scan_type=scan_type)
                # for testing
                if status.state == "SUCCESS" and result_file_name:
                    with open(result_file_name, "w+") as f:
                        json.dump(results , f, indent=2)

                if not result_file_name:
                    console.print(f"Results: {results}",style="bold orange1")
                stop = True

       
    except Exception as e:
        console.print(f"Error while testing:{str(e)}",style="bold red")



#------------------------------------------ testing SAST , tested and works ✅ ---------------------------------------------------------------------------
# exclude_path_arrays = [["frontend"],["api_routes"],["mcpscan_utils"],["llm_scan_utils"],["normal_scan_utils"],["virus_scan_utils"],["test.py"],["graph.py"]]
# dict_context = {
#     "mode":"github",
#     "repo_url":"https://github.com/CyberUltron-Nikhil/RiskPilot.git",
#     "PAT":"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",
#     }
# sast_kwargs = {
#     "repo_dict_context":dict_context,
#     "app_lang":"python",
#     "exclude_path_arrays":exclude_path_arrays
# }
# zip_context = {
#     "bucket_name":"devsecshield-storage",
#     "object_name":"RiskPilot-main (1).zip"
# }
# sast_kwargs_2 = {
#     "zip_dict_context":zip_context,
#     "app_lang":"python",
#     "exclude_path_arrays":exclude_path_arrays
# }
# test(task_name="scan_worker.sast",kwargs=sast_kwargs_2,result_file_name="worker_sast_agent_results_testing.json",scan_type="sast")




#------------------------------------------ testing IAC , tested and works ✅ ---------------------------------------------------------------------------
# dict_context = {
#     "mode":"github",
#     "repo_url":"https://github.com/CyberUltron-Nikhil/IAC_testing.git",
#     "PAT":"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",
#     }
# iac_dict_contexts = [
#     {
#         "mode":"terraform",
#     },
#     {
#         "mode":"k8s",
#         "include_path_arrays":[["kubernetes"]]
#     },
#     {
#         "mode":"pulumi",
#         "include_path_arrays":[["pulumi"]]
#     }
# ]
# iac_kwargs = {
#     "repo_dict_context":dict_context,
#     "iac_dict_contexts":iac_dict_contexts,
# }
# iac_zip_context = {
#     "bucket_name":"devsecshield-storage",
#     "object_name":"IAC_testing-main.zip"
# }
# iac_kwargs_2 = {
#     "zip_dict_context":iac_zip_context,
#     "iac_dict_contexts":iac_dict_contexts,
# }
# test(task_name="scan_worker.iac",kwargs=iac_kwargs,result_file_name="worker_iac_agent_results_testing.json" ,scan_type="iac")


#------------------------------------------ testing SBOM , tested and works ✅ ---------------------------------------------------------------------------
# dict_context = {
#     "mode":"github",
#     "repo_url":"https://github.com/CyberUltron-Nikhil/RiskPilot.git",
#     "PAT":"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",
# }
# sbom_kwargs={
#     "repo_dict_context":dict_context,
# }
# sbom_zip_context = {
#     "bucket_name":"devsecshield-storage",
#     "object_name":"RiskPilot-main (1).zip"
# }
# sbom_kwargs_2 = {
#     "zip_dict_context":sbom_zip_context,
# }
# sbom_file_context = {
#     "bucket_name":"devsecshield-storage",
#     "object_name":"test_cDX_sbom.json"
# }
# sbom_kwargs_3 = {
#     "file_dict_context":sbom_file_context,
# }
# test(task_name="scan_worker.sbom_sca",kwargs=sbom_kwargs_3,result_file_name="worker_sbom_agent_results_testing.json",scan_type="sbom")


#------------------------------------------ testing SAST estimation , tested and works ✅ ---------------------------------------------------------------------------
# exclude_path_arrays = [["frontend"],["api_routes"],["mcpscan_utils"],["llm_scan_utils"],["normal_scan_utils"],["virus_scan_utils"],["test.py"],["graph.py"]]
# dict_context = {
#     "mode":"github",
#     "repo_url":"https://github.com/CyberUltron-Nikhil/RiskPilot.git",
#     "PAT":"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",
#     }
# sast_kwargs = {
#     "repo_dict_context":dict_context,
#     "app_lang":"python",
#     "exclude_path_arrays":exclude_path_arrays
# }
# zip_context = {
#     "bucket_name":"devsecshield-storage",
#     "object_name":"RiskPilot-main (1).zip"
# }
# sast_kwargs_2 = {
#     "zip_dict_context":zip_context,
#     "app_lang":"python",
#     "exclude_path_arrays":exclude_path_arrays
# }
# test(task_name="scan_worker.sast_estimation",kwargs=sast_kwargs_2,scan_type="sast")
# test(task_name="scan_worker.sast_estimation",kwargs=sast_kwargs,scan_type="sast")




#------------------------------------------ testing IAC estimation , tested and works ✅ ---------------------------------------------------------------------------
# dict_context = {
#     "mode":"github",
#     "repo_url":"https://github.com/CyberUltron-Nikhil/IAC_testing.git",
#     "PAT":"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",
#     }
# iac_dict_contexts = [
#     {
#         "mode":"terraform",
#     },
#     {
#         "mode":"k8s",
#         "include_path_arrays":[["kubernetes"]]
#     },
#     {
#         "mode":"pulumi",
#         "include_path_arrays":[["pulumi"]]
#     }
# ]
# iac_kwargs = {
#     "repo_dict_context":dict_context,
#     "iac_dict_contexts":iac_dict_contexts,
# }
# iac_zip_context = {
#     "bucket_name":"devsecshield-storage",
#     "object_name":"IAC_testing-main.zip"
# }
# iac_kwargs_2 = {
#     "zip_dict_context":iac_zip_context,
#     "iac_dict_contexts":iac_dict_contexts,
# }
# test(task_name="scan_worker.iac_estimation",kwargs=iac_kwargs,scan_type="iac")
# test(task_name="scan_worker.iac_estimation",kwargs=iac_kwargs_2,scan_type="iac")


#------------------------------------------ testing SBOM estimation , tested and works ✅ ---------------------------------------------------------------------------
# dict_context = {
#     "mode":"github",
#     "repo_url":"https://github.com/CyberUltron-Nikhil/RiskPilot.git",
#     "PAT":"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",
# }
# sbom_kwargs={
#     "repo_dict_context":dict_context,
# }
# sbom_zip_context = {
#     "bucket_name":"devsecshield-storage",
#     "object_name":"RiskPilot-main (1).zip"
# }
# sbom_kwargs_2 = {
#     "zip_dict_context":sbom_zip_context,
# }
# sbom_file_context = {
#     "bucket_name":"devsecshield-storage",
#     "object_name":"test_cDX_sbom.json"
# }
# sbom_kwargs_3 = {
#     "file_dict_context":sbom_file_context,
# }
# test(task_name="scan_worker.sbom_sca_estimation",kwargs=sbom_kwargs_3,scan_type="sbom")
# test(task_name="scan_worker.sbom_sca_estimation",kwargs=sbom_kwargs_2,scan_type="sbom")
# test(task_name="scan_worker.sbom_sca_estimation",kwargs=sbom_kwargs,scan_type="sbom")
