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
except Exception as e :
    Console().print("Set username and password env variables to access broker",style="bold red")



simple_app = Celery('testing_tasks',
                    broker=f"amqp://{username}:{password}@localhost:5672",
                    backend='rpc://')



def test(
    task_name:str,
    kwargs:dict,
    result_file_name:str ):

    try:
       
        r = simple_app.send_task(task_name, kwargs=kwargs)
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
            if status.state != "PENDING":
                stop = True
       
    except Exception as e:
        Console().print(f"Error while testing:{str(e)}",style="bold red")



#------------------------------------------ testing SAST , ✅ Tested and works ---------------------------------------------------------------------------
# sast_kwargs = {
#     "repo_url":"https://github.com/CyberUltron-Nikhil/RiskPilot",
#     "PAT":"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",
#     "app_lang":"javascript",
# }
# test(task_name="scan_worker.sast",kwargs=sast_kwargs,result_file_name="sast_results_testing.json")



#------------------------------------------ testing IAC , ✅ Tested and works ---------------------------------------------------------------------------
# iac_kwargs = {
#     "repo_url":"https://github.com/CyberUltron-Nikhil/devsecshield",
#     "PAT":"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",
# }
# test(task_name="scan_worker.iac",kwargs=iac_kwargs,result_file_name="iac_results_testing.json")


#------------------------------------------ testing MCP , ✅ Tested and works ---------------------------------------------------------------------------
# json_data = json.load(open("C:\\Users\\HP\\Desktop\\DevSecShield\\rabbitmq\\worker\\tools\\mcp_utils\\test-server-mcp.json"))
# string_json = str(json_data)
# string_json = string_json.replace("'", '"')
# mcp_kwargs = {
#     "server_config_json":string_json
# }
# test(task_name="scan_worker.mcp",kwargs=mcp_kwargs,result_file_name="mcp_results_testing.json")

#------------------------------------------ testing SBOM , ✅ Tested and works  ---------------------------------------------------------------------------
# sbom_kwargs={
#     "repo_url":"https://github.com/CyberUltron-Nikhil/RiskPilot",
#     "PAT":"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",
# }
# test(task_name="scan_worker.sbom_sca",kwargs=sbom_kwargs,result_file_name="sbom_results_testing.json")

#------------------------------------------ testing GItleaks , ✅ Tested and works ---------------------------------------------------------------------------
# gitleaks_kwargs={
#     "repo_url":"https://github.com/CyberUltron-Nikhil/RiskPilot",
#     "PAT":"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",
# }
# test(task_name="scan_worker.gitleaks",kwargs=gitleaks_kwargs,result_file_name="gitleaks_results_testing.json")

#------------------------------------------ testing discovery , ✅ Tested and works ---------------------------------------------------------------------------
# discovery_kwargs={
#     "repo_url":"https://github.com/yacwagh/double-trust",
#     "PAT":"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"
# }
# test(task_name="scan_worker.discovery",kwargs=discovery_kwargs,result_file_name="discovery_results_testing.json")

#------------------------------------------ testing llm ---------------------------------------------------------------------------
llm_kwargs={
    "model_type":"custom",
    "model_name":"gpt-4o",
    "headers":{
                "Authorization": "Bearer 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",
                "Content-Type": "application/json"
                },
    "request_template":{
            "model": "gpt-4o",
            "input": "$INPUT"
          },
    "response_json_field":"$.output[0].content[0].text",
    "probes":"malwaregen.TopLevel",
    "model_uri":"https://api.openai.com/v1/responses",
}
test(task_name="scan_worker.llm_benchmark",kwargs=llm_kwargs,result_file_name="llm_results_testing.json")






