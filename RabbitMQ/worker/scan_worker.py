from typing import Literal, Optional
from celery import Celery
from rich.console import Console
from celery.result import AsyncResult
import time 
from dotenv import load_dotenv
import os
import sys
from tools.sast_utils.sast_runner import run_sast_scan
from tools.sbom_sca_utils.sbom_runner import run_sbom_scan
from tools.iac_utils.iac_runner import run_iac_scan
from tools.gitleaks_utils.gitleaks_runner import run_gitleaks_scan
from tools.discovery_utils.discovery_runner import run_discovery_scan
from tools.llm_utils.llm_runner import run_garak_scan
from tools.mcp_utils.mcp_runner import run_mcp_scan
from tools.context.scan_context import validate_dict_with_context
import json

console = Console()

# os.environ["IS_DOCKER_CONTAINER"] = "False"  # ⚠️⚠️⚠️⚠️⚠️⚠️⚠️

#====================================== Setting credentials to connect to broker ================================================================
try:
    load_dotenv()
    is_docker_container = os.getenv("IS_DOCKER_CONTAINER")
    if is_docker_container and is_docker_container == "True":
        console.print(f"Docker container detected",style="bold green")

        #broker url
        username = os.getenv("RABBIT_ADMIN_USERNAME")
        password = os.getenv("RABBIT_ADMIN_PASSWORD")
        broker_url = f"amqp://{username}:{password}@13.203.233.15:5672"

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
        broker_url = f"amqp://{username}:{password}@localhost:5672"

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
    # app = Celery('worker', broker=f"amqp://{username}:{password}@localhost:5672",backend='rpc://')
    # app = Celery('worker', broker=f"amqp://{username}:{password}@localhost:5672",backend=mongo_url)
    app = Celery('worker', broker=broker_url,backend=mongo_url)
    app.conf.update(
        RESULT_PERSISTENT=True,
        TASK_TRACK_STARTED=True,
    )
    console.print(f"Celery App instantiated",style="bold green")



    # ------------------------------------------- SAST Scanning task -------------------------------------------------------------------------------------------
    """
    You can add track_started=True to the task decorator to track the start time of the task. i.e. "STARTED" state will be used to track the start time of the task.
    example : @app.task(track_started=True)

    If you are enabling this , then make sure the frontend polls even status is "started" , becase as of now it only polls when status is "pending".
    """
    
    @app.task(track_started=True)
    def sast(
        dict_context: dict , 
        app_lang:Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"]):


        try :
            
            # STEP [ 1 ] : =========== Validate the context ======================
            context = validate_dict_with_context(dict_context)
            
            # STEP [ 2 ] : =========== Run the sast scan ======================
            results = run_sast_scan( context=context,app_lang=app_lang)  

            # STEP [ 3 ] : =========== Return the results ======================
            return results

        except Exception as e:
            console.print(f"Error in sast task: {str(e)}",style="bold red")
            raise e
    console.print(f"Registered SAST task",style="bold green")


     # ------------------------------------------- SBOM + SCA Scanning task -------------------------------------------------------------------------------------------
    @app.task(track_started=True)
    def sbom_sca(
        dict_context: dict , 
        sbom_json_file: str | None = None # this is optional and only used for testing purposes
        ):

        
        context = validate_dict_with_context(dict_context)

        results = run_sbom_scan(
            context=context,
            sbom_json_file=sbom_json_file,
        )  
        return results 
    console.print(f"Registered SBOM SCA task",style="bold green")


     # ------------------------------------------- IAC Scanning task -------------------------------------------------------------------------------------------
    @app.task(track_started=True)
    def iac(
        dict_context: dict , 
        mode: Literal["tfsec", "trivy"] = "tfsec", # this is optional and only used for testing purposes
        ):


        context = validate_dict_with_context(dict_context)
        results = run_iac_scan(
            context=context,
            mode=mode,
        ) 
        return results 
    console.print(f"Registered IAC task with context pattern",style="bold green")

     # ------------------------------------------- Agent discovery Scanning task -------------------------------------------------------------------------------------------
    @app.task(track_started=True)
    def discovery(
        dict_context: dict , 
        ):

        context = validate_dict_with_context(dict_context)

        results = run_discovery_scan(
            context=context,
        )  

        return results
    console.print(f"Registered Agent discovery task",style="bold green")


     # ------------------------------------------- LLM benchmark Scanning task -------------------------------------------------------------------------------------------
    @app.task(track_started=True)
    def llm_benchmark(
        model_type: Literal["openai", "anthropic", "gemini","custom"],
        model_name: str,
        probes: Literal["all", "ansiescape", "atkgen", "audio", "av_spam_scanning", "continuation", "dan", "divergence", "doctor", "donotanswer", "encoding", "exploitation", "fileformats", "glitch", "goodside", "grandma", "latentinjection", "leakreplay", "lmrc", "malwaregen", "misleading", "packagehallucination", "phrasing", "promptinject", "realtoxicityprompts", "sata", "snowball", "suffix", "tap", "test", "topic", "visual_jailbreak", "xss"] = "all",
        api_key: Optional[str] = None,
        headers: Optional[dict] = None,
        request_template: Optional[dict] = None,
        response_json_field: Optional[str] = None,
        generations: Optional[int] = 1,
        method: Literal["get", "post"] = "post",
        model_uri: Optional[str] = None,):

        
        if (model_type not in ["openai", "anthropic", "gemini","custom"]):
            raise Exception("Arguments are invalid/incorrect")

        results = run_garak_scan(
            model_type=model_type,
            model_name=model_name,
            probes=probes,
            api_key=api_key,
            headers=headers,
            request_template=request_template,
            response_json_field=response_json_field,
            generations=generations,
            method=method,
            model_uri=model_uri,
        ) 

        # for testing purposes , using a mock result
        # for i in range(10):
        #     console.print(f"Sleeping {i} ....",style="bold yellow")
        #     time.sleep(1)
        # with open("mock_result.json", "r") as f:
        #     results = json.load(f)

        return results 
    console.print(f"Registered LLM task",style="bold green")


     # ------------------------------------------- MCP Scanning task -------------------------------------------------------------------------------------------
    @app.task(track_started=True)
    def mcp(
        server_config_json:str
        ):

        
        if not server_config_json:
            raise Exception("Arguments are invalid/incorrect")

        results = run_mcp_scan(
            server_config_json=server_config_json
        )

        return results 

    console.print(f"Registered MCP task",style="bold green")


     # ------------------------------------------- Gitleaks Scanning task -------------------------------------------------------------------------------------------
    @app.task(track_started=True)  
    def gitleaks(
        dict_context: dict , ):

        context = validate_dict_with_context(dict_context)

        results = run_gitleaks_scan(
            context=context,
        )  
        return results
    console.print(f"Registered Gitleaks task",style="bold green")

except Exception as e:
    console.print(f"Error occured while registering tasks : {str(e)}",style="bold red")