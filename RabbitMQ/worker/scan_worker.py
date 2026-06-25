import json
from typing import Literal, Optional
from celery import Celery, Task
from rich.console import Console
from celery.result import AsyncResult
import time 
from dotenv import load_dotenv
import os
import sys
from helpers.context.progress_writer import StateUpdateWriter
from helpers.tools.mcp_agent.context import MCPContext
from helpers.tools.mcp_agent.main import MCPAgent
from helpers.tools.sast_agent.main import SASTAgent
from helpers.tools.sca_sbom_agent.main import SCASBOMAgent
from helpers.tools.iac_agent.main import IACAgent
from helpers.tools.cbom_agent.main import CBOMAgent
from helpers.tools.ai_bom_agent.main import AIBOMAgent
from helpers.tools.iac_agent.context import IACTypeContext, validate_dict_with_iac_context
from helpers.tools.llm_agent.context import LLMBenchmarkingContext
from helpers.tools.llm_agent.main import LLMBenchmarkingAgent
from helpers.context.s3_utils import delete_file
from helpers.context.scan_context import validate_dict_with_context, validate_dict_with_zip_context, validate_dict_with_file_context

console = Console()

#====================================== Setting credentials to connect to broker ================================================================
try:
    load_dotenv()
    is_docker_container = os.getenv("IS_DOCKER_CONTAINER", "False") == "True"
    
    # Hosts: Docker uses production host, local uses env var with localhost default
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
    # app = Celery('worker', broker=f"amqp://{username}:{password}@localhost:5672",backend='rpc://')
    # app = Celery('worker', broker=f"amqp://{username}:{password}@localhost:5672",backend=mongo_url)
    app = Celery('worker', broker=broker_url,backend=mongo_url)
    app.conf.update(
        RESULT_PERSISTENT=True,
        TASK_TRACK_STARTED=True,
        # SECURITY: Global task timeout defaults to prevent unbounded execution
        task_time_limit=900,           # Hard kill after 15 minutes
        task_soft_time_limit=600,      # SoftTimeLimitExceeded after 10 minutes
        task_acks_late=True,           # Re-queue if worker dies
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,  # Prevent greedy prefetching
    )
    console.print(f"Celery App instantiated",style="bold green")



    # ------------------------------------------- SAST Scanning task -------------------------------------------------------------------------------------------
    """
    You can add track_started=True to the task decorator to track the start time of the task. i.e. "STARTED" state will be used to track the start time of the task.
    example : @app.task(track_started=True)

    If you are enabling this , then make sure the frontend polls even status is "started" , becase as of now it only polls when status is "pending".
    """
    
    @app.task(track_started=True , bind=True)
    def sast(
        self,
        app_lang:Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"],
        repo_dict_context: dict | None = None , 
        zip_dict_context: dict | None = None , 
        exclude_path_arrays:Optional[list[list[str]]] = None,
        ):


        try :

            start_time = time.time()
            
            # STEP [ 1 ] : =========== Validate the context ======================
            repo_context , zip_context = None, None
            if repo_dict_context:
                repo_context = validate_dict_with_context(repo_dict_context)
            if zip_dict_context:
                zip_context = validate_dict_with_zip_context(zip_dict_context)

            state_update_writer = StateUpdateWriter(self)
            
            # STEP [ 2 ] : =========== Initialize the agent , and run the agent ======================
            if repo_context:
                agent = SASTAgent(
                    context=repo_context,
                    app_lang=app_lang,
                    exclude_path_arrays=exclude_path_arrays,
                    state_update_writer=state_update_writer,
                )
                result , metadata = agent.run_agent()
                parsed_output = agent.to_dict_list(result)
                end_time = time.time()
                duration_of_scan = end_time - start_time
                return {
                    "results": parsed_output,
                    "metadata": metadata,
                    "duration_of_scan": duration_of_scan,
                }
            elif zip_context:
                agent = SASTAgent(
                    zip_context=zip_context,
                    app_lang=app_lang,
                    exclude_path_arrays=exclude_path_arrays,
                    state_update_writer=state_update_writer,
                )
                result , metadata = agent.run_agent()
                parsed_output = agent.to_dict_list(result)

                end_time = time.time()
                duration_of_scan = end_time - start_time
                return {
                    "results": parsed_output,
                    "metadata": metadata,
                    "duration_of_scan": duration_of_scan,
                }
            else:
                raise Exception("No context provided")

        except Exception as e:
            console.print(f"Error in sast task: {str(e)}",style="bold red")
            raise e
        finally:
            if zip_context:
                # delete the files from bucket 
                if delete_file(zip_context.bucket_name, zip_context.object_name):
                    console.print(f"Deleted zip file from bucket",style="bold green")
                else:
                    console.print(f"Error in deleting zip file from bucket",style="bold red")

    console.print(f"Registered SAST task",style="bold green")


     # ------------------------------------------- SBOM + SCA Scanning task -------------------------------------------------------------------------------------------
    @app.task(track_started=True , bind=True)
    def sbom_sca(
        self,
        repo_dict_context: dict | None = None , 
        zip_dict_context: dict | None = None , 
        file_dict_context: dict | None = None , 
        ):

        
        try:
            start_time = time.time()
            # STEP [ 1 ] : =========== Validate the context ======================
            repo_context , zip_context , file_context = None, None, None
            if repo_dict_context:
                repo_context = validate_dict_with_context(repo_dict_context)
            elif zip_dict_context:
                zip_context = validate_dict_with_zip_context(zip_dict_context)
            elif file_dict_context:
                file_context = validate_dict_with_file_context(file_dict_context)
            else:
                raise Exception("No context provided")

            
            state_update_writer = StateUpdateWriter(self)

            

            # STEP [ 3 ] : =========== Initialize the agent , and run the agent ======================
            if repo_context:
                agent = SCASBOMAgent(
                    context=repo_context,
                    state_update_writer=state_update_writer,
                )
                result = agent.run_agent()
                parsed_output = agent.to_dict_list(result)
                end_time = time.time()
                duration_of_scan = end_time - start_time
                return {
                    "results": parsed_output,
                    "duration_of_scan": duration_of_scan,
                }
            elif zip_context:
                agent = SCASBOMAgent(
                    zip_context=zip_context,
                    state_update_writer=state_update_writer,
                )
                result = agent.run_agent()
                parsed_output = agent.to_dict_list(result)
                end_time = time.time()
                duration_of_scan = end_time - start_time
                return {
                    "results": parsed_output,
                    "duration_of_scan": duration_of_scan,
                }
            elif file_context:
                agent = SCASBOMAgent(
                    sbom_json_file_context=file_context,
                    state_update_writer=state_update_writer,
                )
                result = agent.run_agent()
                parsed_output = agent.to_dict_list(result)
                end_time = time.time()
                duration_of_scan = end_time - start_time
                return {
                    "results": parsed_output,
                    "duration_of_scan": duration_of_scan,
                }
            else:
                raise Exception("Unable to run sbom_sca scan with the provided context")

        except Exception as e:
            console.print(f"Error in sbom_sca task: {str(e)}",style="bold red")
            raise e
        finally:
            if zip_context:
                if delete_file(zip_context.bucket_name, zip_context.object_name):
                    console.print(f"Deleted zip file from bucket",style="bold green")
                else:
                    console.print(f"Error in deleting zip file from bucket",style="bold red")
            if file_context:
                if delete_file(file_context.bucket_name, file_context.object_name):
                    console.print(f"Deleted file from bucket",style="bold green")
                else:
                    console.print(f"Error in deleting file from bucket",style="bold red")

       
    console.print(f"Registered SBOM SCA task",style="bold green")


     # ------------------------------------------- IAC Scanning task -------------------------------------------------------------------------------------------
    @app.task(track_started=True , bind=True)
    def iac(
        self,
        iac_dict_contexts: list[dict],
        repo_dict_context: dict | None = None , 
        zip_dict_context: dict | None = None , 
        ):


        try:
            start_time = time.time()

            # STEP [ 1 ] : =========== Validate the context ======================
            repo_context , zip_context = None, None
            if repo_dict_context:
                repo_context = validate_dict_with_context(repo_dict_context)
            elif zip_dict_context:
                zip_context = validate_dict_with_zip_context(zip_dict_context)
            else:
                raise Exception("No context provided")
            

            iac_contexts : list[IACTypeContext] = []
            if not iac_dict_contexts or len(iac_dict_contexts) == 0:
                raise Exception("IAC contexts not provided")
            else: 
                iac_contexts = [validate_dict_with_iac_context(iac_dict_context) for iac_dict_context in iac_dict_contexts]

            
            state_update_writer = StateUpdateWriter(self)
            
            # STEP [ 3 ] : =========== Initialize the agent , and run the agent ======================
            if repo_context:
                agent = IACAgent(
                    context=repo_context,
                    iac_contexts=iac_contexts,
                    state_update_writer=state_update_writer,
                )
                result , dependency_diagram , metadata = agent.run_agent()  
                parsed_output = agent.to_dict_list(result)
                end_time = time.time()
                duration_of_scan = end_time - start_time
                return {
                    "results": parsed_output,
                    "metadata": metadata,
                    "dependency_diagram": dependency_diagram,
                    "duration_of_scan": duration_of_scan,
                }
            elif zip_context:
                agent = IACAgent(
                    zip_context=zip_context,
                    iac_contexts=iac_contexts,
                    state_update_writer=state_update_writer,
                )
                result , dependency_diagram , metadata = agent.run_agent()
                parsed_output = agent.to_dict_list(result)
                end_time = time.time()
                duration_of_scan = end_time - start_time
                return {
                    "results": parsed_output,
                    "metadata": metadata,
                    "dependency_diagram": dependency_diagram,
                    "duration_of_scan": duration_of_scan,
                }
            else:
                raise Exception("Unable to run iac scan with the provided context")
        
        except Exception as e:
            console.print(f"Error in iac task: {str(e)}",style="bold red")
            raise e
        finally:
            if zip_context:
                if delete_file(zip_context.bucket_name, zip_context.object_name):
                    console.print(f"Deleted zip file from bucket",style="bold green")
                else:
                    console.print(f"Error in deleting zip file from bucket",style="bold red")

    console.print(f"Registered IAC task with context pattern",style="bold green")



    @app.task(track_started=True, bind=True , soft_time_limit=1200 , time_limit=1800)
    def mcp_scan(
        self:Task,
        mcp_dict_context: dict,
        ):
        
        try:
            start_time = time.time()
            state_update_writer = StateUpdateWriter(self)
            mcp_context = MCPContext.model_validate_json(json.dumps(mcp_dict_context))
            print(mcp_context)
            mcp_agent = MCPAgent(
                mcp_context=mcp_context,
                state_update_writer=state_update_writer,
            )
            result = mcp_agent.run_agent()
            end_time = time.time()
            duration_of_scan = end_time - start_time
            return {
                "results": result,
                "duration_of_scan": duration_of_scan,
            }
        except Exception as e:
            console.print(f"Error in mcp_scan task: {str(e)}",style="bold red")
            raise e
    
    @app.task(track_started=True, bind=True)
    def llm_benchmark_scan(
        self:Task,
        llm_benchmark_dict_context: dict,
        ):
        try:
            start_time = time.time()
            state_update_writer = StateUpdateWriter(self)
            llm_benchmark_context = LLMBenchmarkingContext.model_validate_json(json.dumps(llm_benchmark_dict_context))
            llm_benchmark_agent = LLMBenchmarkingAgent(
                llm_benchmarking_context=llm_benchmark_context,
                state_update_writer=state_update_writer,
            )
            result , metadata = llm_benchmark_agent.run_agent()
            end_time = time.time()
            duration_of_scan = end_time - start_time
            return {
                "results": result,
                "metadata": metadata,
                "duration_of_scan": duration_of_scan,
            }
        except Exception as e:
            console.print(f"Error in llm_benchmark_scan task: {str(e)}",style="bold red")
            raise e


    # -------------------------------------------------- Estimation tasks -----------------------------------------------------------------------

    
    @app.task(track_started=True)
    def mcp_estimation(
        mcp_dict_context: dict,
        ):
        try:
            mcp_context = MCPContext.model_validate_json(json.dumps(mcp_dict_context))
            print(mcp_context)
            mcp_agent = MCPAgent(
                mcp_context=mcp_context,
            )
            result = mcp_agent.estimate_credits_required()
            return result
        except Exception as e:
            console.print(f"Error in mcp_estimation task: {str(e)}",style="bold red")
            raise e
    
    @app.task(track_started=True)
    def llm_benchmark_estimation(
        llm_benchmark_dict_context: dict,
        ):
        try:
            llm_benchmark_context = LLMBenchmarkingContext.model_validate_json(json.dumps(llm_benchmark_dict_context))
            llm_benchmark_agent = LLMBenchmarkingAgent(
                llm_benchmarking_context=llm_benchmark_context,
            )
            result = llm_benchmark_agent.estimate_credits_required()
            return result
        except Exception as e:
            console.print(f"Error in llm_benchmark_estimation task: {str(e)}",style="bold red")
            raise e
    
    
    @app.task(track_started=True)
    def sast_estimation(
        app_lang:Literal["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"],
        repo_dict_context: dict | None = None , 
        zip_dict_context: dict | None = None , 
        exclude_path_arrays:Optional[list[list[str]]] = None,
        ):


        try :


            # STEP [ 1 ] : =========== Validate the context ======================
            repo_context , zip_context = None, None
            if repo_dict_context:
                repo_context = validate_dict_with_context(repo_dict_context)
            if zip_dict_context:
                zip_context = validate_dict_with_zip_context(zip_dict_context)
            
            # STEP [ 2 ] : =========== Initialize the agent , and estimate the credits required ======================
            agent = None
            if repo_context:
                agent = SASTAgent(
                    context=repo_context,
                    app_lang=app_lang,
                    exclude_path_arrays=exclude_path_arrays,
                )
            elif zip_context:
                agent = SASTAgent(
                    zip_context=zip_context,
                    app_lang=app_lang,
                    exclude_path_arrays=exclude_path_arrays,
                )
            else:
                raise Exception("No context provided")
            
            credits_required = agent.estimate_credits_required()
            return credits_required

        except Exception as e:
            console.print(f"Error in sast_estimation task: {str(e)}",style="bold red")
            return -1 # return -1 to indicate that the estimation failed
        finally:
            if zip_context:
                if delete_file(zip_context.bucket_name, zip_context.object_name):
                    console.print(f"Deleted zip file from bucket",style="bold green")
                else:
                    console.print(f"Error in deleting zip file from bucket",style="bold red")
    console.print(f"Registered SAST estimation task",style="bold green")


     # ------------------------------------------- SBOM + SCA Scanning task -------------------------------------------------------------------------------------------
    @app.task(track_started=True)
    def sbom_sca_estimation(
        repo_dict_context: dict | None = None , 
        zip_dict_context: dict | None = None , 
        file_dict_context: dict | None = None , 
        ):

        
        try:
            
            # STEP [ 1 ] : =========== Validate the context ======================
            repo_context , zip_context , file_context = None, None, None
            if repo_dict_context:
                repo_context = validate_dict_with_context(repo_dict_context)
            elif zip_dict_context:
                zip_context = validate_dict_with_zip_context(zip_dict_context)
            elif file_dict_context:
                file_context = validate_dict_with_file_context(file_dict_context)
            else:
                raise Exception("No context provided")
            

            # STEP [ 2 ] : =========== Initialize the agent , and estimate the credits required ======================
            agent = None
            if repo_context:
                agent = SCASBOMAgent(
                    context=repo_context,
                )
            elif zip_context:
                agent = SCASBOMAgent(
                    zip_context=zip_context,
                )
            elif file_context:
                agent = SCASBOMAgent(
                    sbom_json_file_context=file_context,
                )
            else:
                raise Exception("Unable to run sbom_sca scan with the provided context")
            

            credits_required = agent.estimate_credits_required()
            return credits_required

        except Exception as e:
            console.print(f"Error in sbom_sca_estimation task: {str(e)}",style="bold red")
            return -1 # return -1 to indicate that the estimation failed
        finally:
            if zip_context:
                if delete_file(zip_context.bucket_name, zip_context.object_name):
                    console.print(f"Deleted zip file from bucket",style="bold green")
                else:
                    console.print(f"Error in deleting zip file from bucket",style="bold red")
            if file_context:
                if delete_file(file_context.bucket_name, file_context.object_name):
                    console.print(f"Deleted file from bucket",style="bold green")
                else:
                    console.print(f"Error in deleting file from bucket",style="bold red")

       
    console.print(f"Registered SBOM SCA estimation task",style="bold green")


     # ------------------------------------------- IAC Scanning task -------------------------------------------------------------------------------------------
    @app.task(track_started=True)
    def iac_estimation(
        iac_dict_contexts: Optional[list[dict]] = None,
        repo_dict_context: dict | None = None , 
        zip_dict_context: dict | None = None , 
        ):


        try:
            # STEP [ 1 ] : =========== Validate the context ======================
            repo_context , zip_context = None, None
            if repo_dict_context:
                repo_context = validate_dict_with_context(repo_dict_context)
            elif zip_dict_context:
                zip_context = validate_dict_with_zip_context(zip_dict_context)
            else:
                raise Exception("No context provided")
            

            iac_contexts : list[IACTypeContext] = []
            if not iac_dict_contexts or len(iac_dict_contexts) == 0:
                raise Exception("IAC contexts not provided")
            else: 
                iac_contexts = [validate_dict_with_iac_context(iac_dict_context) for iac_dict_context in iac_dict_contexts]
            
            
            # STEP [ 2 ] : =========== Initialize the agent , and estimate the credits required ======================
            agent = None
            if repo_context:
                agent = IACAgent(
                    context=repo_context,
                    iac_contexts=iac_contexts,
                )
            elif zip_context:
                agent = IACAgent(
                    zip_context=zip_context,
                    iac_contexts=iac_contexts,
                )
            else:
                raise Exception("Unable to run iac scan with the provided context")
            
            credits_required = agent.estimate_credits_required()
            return credits_required
        
        except Exception as e:
            console.print(f"Error in iac_estimation task: {str(e)}",style="bold red")
            return -1 # return -1 to indicate that the estimation failed
        finally:
            if zip_context:
                if delete_file(zip_context.bucket_name, zip_context.object_name):
                    console.print(f"Deleted zip file from bucket",style="bold green")
                else:
                    console.print(f"Error in deleting zip file from bucket",style="bold red")

    console.print(f"Registered IAC estimation task",style="bold green")


     # ------------------------------------------- CBOM Scanning task -------------------------------------------------------------------------------------------
    @app.task(track_started=True, bind=True)
    def cbom(
        self,
        repo_dict_context: dict | None = None,
        zip_dict_context: dict | None = None,
        file_dict_context: dict | None = None,
        scan_binaries: bool = False,
    ):

        try:
            start_time = time.time()
            # STEP [ 1 ] : =========== Validate the context ======================
            repo_context, zip_context, file_context = None, None, None
            if repo_dict_context:
                repo_context = validate_dict_with_context(repo_dict_context)
            elif zip_dict_context:
                zip_context = validate_dict_with_zip_context(zip_dict_context)
            elif file_dict_context:
                file_context = validate_dict_with_file_context(file_dict_context)
            else:
                raise Exception("No context provided")

            state_update_writer = StateUpdateWriter(self)

            # STEP [ 2 ] : =========== Initialize the agent , and run the agent ======================
            if repo_context:
                agent = CBOMAgent(
                    context=repo_context,
                    scan_binaries=scan_binaries,
                    state_update_writer=state_update_writer,
                )
                result = agent.run_agent()
                parsed_output = agent.to_dict_list(result)
                cbom_json = agent.get_cyclonedx_cbom()
                end_time = time.time()
                duration_of_scan = end_time - start_time
                return {
                    "results": parsed_output,
                    "cbom_json": cbom_json,
                    "duration_of_scan": duration_of_scan,
                }
            elif zip_context:
                agent = CBOMAgent(
                    zip_context=zip_context,
                    scan_binaries=scan_binaries,
                    state_update_writer=state_update_writer,
                )
                result = agent.run_agent()
                parsed_output = agent.to_dict_list(result)
                cbom_json = agent.get_cyclonedx_cbom()
                end_time = time.time()
                duration_of_scan = end_time - start_time
                return {
                    "results": parsed_output,
                    "cbom_json": cbom_json,
                    "duration_of_scan": duration_of_scan,
                }
            elif file_context:
                agent = CBOMAgent(
                    cbom_file_context=file_context,
                    scan_binaries=scan_binaries,
                    state_update_writer=state_update_writer,
                )
                result = agent.run_agent()
                parsed_output = agent.to_dict_list(result)
                cbom_json = agent.get_cyclonedx_cbom()
                end_time = time.time()
                duration_of_scan = end_time - start_time
                return {
                    "results": parsed_output,
                    "cbom_json": cbom_json,
                    "duration_of_scan": duration_of_scan,
                }
            else:
                raise Exception("Unable to run cbom scan with the provided context")

        except Exception as e:
            console.print(f"Error in cbom task: {str(e)}", style="bold red")
            raise e
        finally:
            if zip_context:
                if delete_file(zip_context.bucket_name, zip_context.object_name):
                    console.print(f"Deleted zip file from bucket", style="bold green")
                else:
                    console.print(f"Error in deleting zip file from bucket", style="bold red")
            if file_context:
                if delete_file(file_context.bucket_name, file_context.object_name):
                    console.print(f"Deleted file from bucket", style="bold green")
                else:
                    console.print(f"Error in deleting file from bucket", style="bold red")

    console.print(f"Registered CBOM task", style="bold green")


     # ------------------------------------------- AI BOM Scanning task -------------------------------------------------------------------------------------------
    @app.task(track_started=True, bind=True)
    def ai_bom(
        self,
        repo_dict_context: dict | None = None,
        zip_dict_context: dict | None = None,
        file_dict_context: dict | None = None,
        scan_binaries: bool = False,
    ):

        try:
            start_time = time.time()
            # STEP [ 1 ] : =========== Validate the context ======================
            repo_context, zip_context, file_context = None, None, None
            if repo_dict_context:
                repo_context = validate_dict_with_context(repo_dict_context)
            elif zip_dict_context:
                zip_context = validate_dict_with_zip_context(zip_dict_context)
            elif file_dict_context:
                file_context = validate_dict_with_file_context(file_dict_context)
            else:
                raise Exception("No context provided")

            state_update_writer = StateUpdateWriter(self)

            # STEP [ 2 ] : ===== Resolve the input to a local directory, then run
            # the clinithread-aibom engine via the native adapter (lanes intact).
            # The standalone engine replaces the in-tree scan body; AIBOMAgent is
            # reused ONLY to clone/extract the input into a directory and to keep
            # the existing bucket-cleanup in `finally`. The adapter returns the
            # locked run-object (results + ai_bom_json + ai_bom_compliance +
            # duration_of_scan, plus additive ai_bom_spdx/sarif/graph/scores).
            from aibom.integrations.devsecshield import scan_to_devsecshield

            def _progress(pct: float, message: str) -> None:
                state_update_writer.write_progress_percentage(pct)

            if repo_context:
                agent = AIBOMAgent(
                    context=repo_context,
                    scan_binaries=scan_binaries,
                    state_update_writer=state_update_writer,
                )
                return scan_to_devsecshield(
                    str(agent.directory), level=4, progress=_progress
                )
            elif zip_context:
                agent = AIBOMAgent(
                    zip_context=zip_context,
                    scan_binaries=scan_binaries,
                    state_update_writer=state_update_writer,
                )
                return scan_to_devsecshield(
                    str(agent.directory), level=4, progress=_progress
                )
            elif file_context:
                # Re-ingesting an existing AI-BOM file is a distinct capability
                # the directory-scanning engine does not cover; keep the in-tree
                # agent for this path.
                agent = AIBOMAgent(
                    aibom_file_context=file_context,
                    scan_binaries=scan_binaries,
                    state_update_writer=state_update_writer,
                )
                result = agent.run_agent()
                return {
                    "results": agent.to_dict_list(result),
                    "ai_bom_json": agent.get_aibom_json(),
                    "ai_bom_compliance": agent.get_compliance_report(),
                    "duration_of_scan": time.time() - start_time,
                }
            else:
                raise Exception("Unable to run ai_bom scan with the provided context")

        except Exception as e:
            console.print(f"Error in ai_bom task: {str(e)}", style="bold red")
            raise e
        finally:
            if zip_context:
                if delete_file(zip_context.bucket_name, zip_context.object_name):
                    console.print(f"Deleted zip file from bucket", style="bold green")
                else:
                    console.print(f"Error in deleting zip file from bucket", style="bold red")
            if file_context:
                if delete_file(file_context.bucket_name, file_context.object_name):
                    console.print(f"Deleted file from bucket", style="bold green")
                else:
                    console.print(f"Error in deleting file from bucket", style="bold red")

    console.print(f"Registered AI BOM task", style="bold green")


     # ------------------------------------------- CBOM Estimation task -------------------------------------------------------------------------------------------
    @app.task(track_started=True)
    def cbom_estimation(
        repo_dict_context: dict | None = None,
        zip_dict_context: dict | None = None,
        file_dict_context: dict | None = None,
        scan_binaries: bool = False,
    ):

        try:
            # STEP [ 1 ] : =========== Validate the context ======================
            repo_context, zip_context, file_context = None, None, None
            if repo_dict_context:
                repo_context = validate_dict_with_context(repo_dict_context)
            elif zip_dict_context:
                zip_context = validate_dict_with_zip_context(zip_dict_context)
            elif file_dict_context:
                file_context = validate_dict_with_file_context(file_dict_context)
            else:
                raise Exception("No context provided")

            # STEP [ 2 ] : =========== Initialize the agent , and estimate the credits required ======================
            agent = None
            if repo_context:
                agent = CBOMAgent(
                    context=repo_context,
                    scan_binaries=scan_binaries,
                )
            elif zip_context:
                agent = CBOMAgent(
                    zip_context=zip_context,
                    scan_binaries=scan_binaries,
                )
            elif file_context:
                agent = CBOMAgent(
                    cbom_file_context=file_context,
                    scan_binaries=scan_binaries,
                )
            else:
                raise Exception("Unable to run cbom scan with the provided context")

            credits_required = agent.estimate_credits_required()
            return credits_required

        except Exception as e:
            console.print(f"Error in cbom_estimation task: {str(e)}", style="bold red")
            import traceback
            console.print(traceback.format_exc(), style="dim red")
            return -1  # return -1 to indicate that the estimation failed
        finally:
            if zip_context:
                if delete_file(zip_context.bucket_name, zip_context.object_name):
                    console.print(f"Deleted zip file from bucket", style="bold green")
                else:
                    console.print(f"Error in deleting zip file from bucket", style="bold red")
            if file_context:
                if delete_file(file_context.bucket_name, file_context.object_name):
                    console.print(f"Deleted file from bucket", style="bold green")
                else:
                    console.print(f"Error in deleting file from bucket", style="bold red")

    console.print(f"Registered CBOM estimation task", style="bold green")


     # ------------------------------------------- AI BOM Estimation task -------------------------------------------------------------------------------------------
    @app.task(track_started=True)
    def ai_bom_estimation(
        repo_dict_context: dict | None = None,
        zip_dict_context: dict | None = None,
        file_dict_context: dict | None = None,
        scan_binaries: bool = False,
    ):

        try:
            # STEP [ 1 ] : =========== Validate the context ======================
            repo_context, zip_context, file_context = None, None, None
            if repo_dict_context:
                repo_context = validate_dict_with_context(repo_dict_context)
            elif zip_dict_context:
                zip_context = validate_dict_with_zip_context(zip_dict_context)
            elif file_dict_context:
                file_context = validate_dict_with_file_context(file_dict_context)
            else:
                raise Exception("No context provided")

            # STEP [ 2 ] : =========== Initialize the agent , and estimate the credits required ======================
            agent = None
            if repo_context:
                agent = AIBOMAgent(
                    context=repo_context,
                    scan_binaries=scan_binaries,
                )
            elif zip_context:
                agent = AIBOMAgent(
                    zip_context=zip_context,
                    scan_binaries=scan_binaries,
                )
            elif file_context:
                agent = AIBOMAgent(
                    aibom_file_context=file_context,
                    scan_binaries=scan_binaries,
                )
            else:
                raise Exception("Unable to run ai_bom scan with the provided context")

            credits_required = agent.estimate_credits_required()
            return credits_required

        except Exception as e:
            console.print(f"Error in ai_bom_estimation task: {str(e)}", style="bold red")
            import traceback
            console.print(traceback.format_exc(), style="dim red")
            return -1  # return -1 to indicate that the estimation failed
        finally:
            if zip_context:
                if delete_file(zip_context.bucket_name, zip_context.object_name):
                    console.print(f"Deleted zip file from bucket", style="bold green")
                else:
                    console.print(f"Error in deleting zip file from bucket", style="bold red")
            if file_context:
                if delete_file(file_context.bucket_name, file_context.object_name):
                    console.print(f"Deleted file from bucket", style="bold green")
                else:
                    console.print(f"Error in deleting file from bucket", style="bold red")

    console.print(f"Registered AI BOM estimation task", style="bold green")








    #  # ------------------------------------------- Agent discovery Scanning task -------------------------------------------------------------------------------------------
    # @app.task(track_started=True)
    # def discovery(
    #     dict_context: dict , 
    #     ):

    #     context = validate_dict_with_context(dict_context)

    #     results = run_discovery_scan(
    #         context=context,
    #     )  

    #     return results
    # console.print(f"Registered Agent discovery task",style="bold green")


    #  # ------------------------------------------- LLM benchmark Scanning task -------------------------------------------------------------------------------------------
    # @app.task(track_started=True)
    # def llm_benchmark(
    #     model_type: Literal["openai", "anthropic", "gemini","custom"],
    #     model_name: str,
    #     probes: Literal["all", "ansiescape", "atkgen", "audio", "av_spam_scanning", "continuation", "dan", "divergence", "doctor", "donotanswer", "encoding", "exploitation", "fileformats", "glitch", "goodside", "grandma", "latentinjection", "leakreplay", "lmrc", "malwaregen", "misleading", "packagehallucination", "phrasing", "promptinject", "realtoxicityprompts", "sata", "snowball", "suffix", "tap", "test", "topic", "visual_jailbreak", "xss"] = "all",
    #     api_key: Optional[str] = None,
    #     headers: Optional[dict] = None,
    #     request_template: Optional[dict] = None,
    #     response_json_field: Optional[str] = None,
    #     generations: Optional[int] = 1,
    #     method: Literal["get", "post"] = "post",
    #     model_uri: Optional[str] = None,):

        
    #     if (model_type not in ["openai", "anthropic", "gemini","custom"]):
    #         raise Exception("Arguments are invalid/incorrect")

    #     results = run_garak_scan(
    #         model_type=model_type,
    #         model_name=model_name,
    #         probes=probes,
    #         api_key=api_key,
    #         headers=headers,
    #         request_template=request_template,
    #         response_json_field=response_json_field,
    #         generations=generations,
    #         method=method,
    #         model_uri=model_uri,
    #     ) 

    #     # for testing purposes , using a mock result
    #     # for i in range(10):
    #     #     console.print(f"Sleeping {i} ....",style="bold yellow")
    #     #     time.sleep(1)
    #     # with open("mock_result.json", "r") as f:
    #     #     results = json.load(f)

    #     return results 
    # console.print(f"Registered LLM task",style="bold green")


    #  # ------------------------------------------- MCP Scanning task -------------------------------------------------------------------------------------------
    # @app.task(track_started=True)
    # def mcp(
    #     server_config_json:str
    #     ):

        
    #     if not server_config_json:
    #         raise Exception("Arguments are invalid/incorrect")

    #     results = run_mcp_scan(
    #         server_config_json=server_config_json
    #     )

    #     return results 

    # console.print(f"Registered MCP task",style="bold green")



except Exception as e:
    console.print(f"Error occured while registering tasks : {str(e)}",style="bold red")