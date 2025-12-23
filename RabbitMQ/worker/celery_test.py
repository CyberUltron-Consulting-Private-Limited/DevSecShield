from dis import disco
import json
from celery import Celery
import time 
from rich.console import Console
from dotenv import load_dotenv
from parsers.utils import parse_scan_results
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
dict_context = {
    "mode":"github",
    "repo_url":"https://github.com/CyberUltron-Nikhil/RiskPilot",
    "PAT":"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",
}
sast_kwargs = {
    "dict_context":dict_context,
    "app_lang":"python",
}
test(task_name="scan_worker.sast",kwargs=sast_kwargs,result_file_name="sast_results_testing.json",scan_type="sast")




#------------------------------------------ testing IAC , ✅ Tested and works with context pattern ✅ ---------------------------------------------------------------------------
dict_context = {
    "mode":"github",
    "repo_url":"https://github.com/CyberUltron-Nikhil/devsecshield",
    "PAT":"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",
}
iac_kwargs = {
    "dict_context":dict_context,
}
test(task_name="scan_worker.iac",kwargs=iac_kwargs,result_file_name="iac_results_testing.json" ,scan_type="iac")


#------------------------------------------ testing MCP , ✅ Tested and works ( doesn't need context pattern ) ✅---------------------------------------------------------------------------
json_data = json.load(open("C:\\Users\\HP\\Desktop\\DevSecShield\\rabbitmq\\worker\\tools\\mcp_utils\\test-server-mcp.json"))
# http_server_config = json.load(open("C:\\Users\\HP\\Desktop\\MCPTest\\mcp_http.json"))
string_json = str(json_data)
string_json = string_json.replace("'", '"')
mcp_kwargs = {
    "server_config_json":string_json
}
test(task_name="scan_worker.mcp",kwargs=mcp_kwargs,result_file_name="mcp_results_testing.json",scan_type="mcp")

#------------------------------------------ testing SBOM , ✅ Tested and works with context pattern ✅ ---------------------------------------------------------------------------
dict_context = {
    "mode":"github",
    "repo_url":"https://github.com/CyberUltron-Nikhil/RiskPilot",
    "PAT":"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",
}
sbom_kwargs={
    "dict_context":dict_context,
}
test(task_name="scan_worker.sbom_sca",kwargs=sbom_kwargs,result_file_name="sbom_results_testing.json",scan_type="sbom")

#------------------------------------------ testing GItleaks , ✅ Tested and works with context pattern ✅ ---------------------------------------------------------------------------dict
dict_context = {
    "mode":"github",
    "repo_url":"https://github.com/CyberUltron-Nikhil/RiskPilot",
    "PAT":"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",
}
gitleaks_kwargs={
    "dict_context":dict_context,
}
test(task_name="scan_worker.gitleaks",kwargs=gitleaks_kwargs,result_file_name="gitleaks_results_testing.json",scan_type="gitleaks")

#------------------------------------------ testing discovery , ✅ Tested and works with context pattern ✅---------------------------------------------------------------------------
dict_context = {
    "mode":"github",
    "repo_url":"https://github.com/yacwagh/double-trust",
    "PAT":"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",
}
discovery_kwargs={
    "dict_context":dict_context,
}
test(task_name="scan_worker.discovery",kwargs=discovery_kwargs,result_file_name="discovery_results_testing.json",scan_type="discovery")

#------------------------------------------ testing llm , ✅ Tested and doesn't need context pattern ✅---------------------------------------------------------------------------
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






