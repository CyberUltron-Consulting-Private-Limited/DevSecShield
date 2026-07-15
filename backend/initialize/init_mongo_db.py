import os
from sqlmodel import SQLModel, create_engine
from pymongo import MongoClient, ASCENDING
from rich.console import Console
import argparse
from dotenv import load_dotenv



def mongo_db_create_collections_and_documents(
    db_name: str = 'devsecshield_backend_server_db' , 
    collection_names: list[str] = [ "message_log", "active_context", "guardrails_logs", "cicd_logs", "scan_findings"]
    ):
    """
    Mongo connection url format : 
    mongodb://<username>:<password>@<host>:<port>
    
    Uses IS_DOCKER_CONTAINER env to pick host; defaults to localhost for local dev.
    """
    load_dotenv()
    try:
        console = Console()
        is_docker = os.getenv("IS_DOCKER_CONTAINER", "False") == "True"
        mongo_host = os.getenv("MONGO_HOST", "devsecshield-mongodb" if is_docker else "localhost")
        mongo_port = os.getenv("MONGO_PORT", "27017")
        
        mongo_username = os.getenv("MONGO_INITDB_ROOT_USERNAME")
        mongo_password = os.getenv("MONGO_INITDB_ROOT_PASSWORD")
        if mongo_username and mongo_password:
            mongo_url = f"mongodb://{mongo_username}:{mongo_password}@{mongo_host}:{mongo_port}/"
        else:
            mongo_url = f"mongodb://{mongo_host}:{mongo_port}/"
        
        # mongo_url = "mongodb://Nikhil:testing123@localhost:27018/"
        mongo_client = MongoClient(mongo_url)
        db = mongo_client[db_name]
        collections = db.list_collection_names()
        console = Console()
        console.print(f"collections: {collections}",style="bold green")
        

        for collection_name in collection_names:
            if collection_name not in collections:
                db.create_collection(collection_name)
                console.print(f"{collection_name} collection created",style="bold green")

        # Create indexes for query performance
        if "scan_findings" in db.list_collection_names():
            db["scan_findings"].create_index([("scan_id", ASCENDING)])
        if "message_log" in db.list_collection_names():
            db["message_log"].create_index([("scan_id", ASCENDING)])
        if "active_context" in db.list_collection_names():
            db["active_context"].create_index([("scan_id", ASCENDING)])
        if "guardrails_logs" in db.list_collection_names():
            db["guardrails_logs"].create_index([("integration_id", ASCENDING)])
            db["guardrails_logs"].create_index([("created_at", ASCENDING)])
        if "cicd_logs" in db.list_collection_names():
            db["cicd_logs"].create_index([("integration_id", ASCENDING)])
            db["cicd_logs"].create_index([("task_id", ASCENDING)])
        console.print("MongoDB indexes created",style="bold green")
        
        console.print(f"collections created",style="bold green")
        console.print(f"list of collections: {db.list_collection_names()}",style="bold green")
    except Exception as e:
        console = Console()
        console.print(f"error creating collections and documents: {e}",style="bold red")


if __name__=="__main__":
    mongo_db_create_collections_and_documents(db_name="new_devsecshield_backend_server_db")