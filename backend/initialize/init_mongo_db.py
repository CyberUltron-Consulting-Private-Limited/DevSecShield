import os
from sqlmodel import SQLModel, create_engine
from pymongo import MongoClient
from rich.console import Console
from backend.models import *
import argparse
from dotenv import load_dotenv



def mongo_db_create_collections_and_documents(
    dev_environment: bool = False,
    db_name: str = 'devsecshield_backend_server_db'
    ):
    """
    Mongo connection url format : 
    mongodb://<username>:<password>@<host>:<port>
    """
    load_dotenv()
    try:
        console = Console()
        console.print(f"dev_environment: {dev_environment}",style="bold green")
        if dev_environment:
            mongo_url = "mongodb://localhost:27017/"
        else: 
            mongo_url = f"mongodb://{os.environ['MONGO_INITDB_ROOT_USERNAME']}:{os.environ['MONGO_INITDB_ROOT_PASSWORD']}@13.203.233.15:27017/"
        
        # mongo_url = "mongodb://Nikhil:testing123@localhost:27018/"
        mongo_client = MongoClient(mongo_url)
        db = mongo_client[db_name]
        collections = db.list_collection_names()
        console = Console()
        console.print(f"collections: {collections}",style="bold green")

        # conversations collection ( removed in the new architecture ⚠️ )
        # if 'conversations' not in collections:
        #     db.create_collection('conversations')
        #     console.print(f"conversations collection created",style="bold green")

        # message_log collection
        if 'message_log' not in collections:
            db.create_collection('message_log')
            console.print(f"message_log collection created",style="bold green")

        # active_context collection
        if 'active_context' not in collections:
            db.create_collection('active_context')
            console.print(f"active_context collection created",style="bold green")

        # guardrail_logs collection
        if 'guardrails_logs' not in collections:
            db.create_collection('guardrails_logs')
            console.print(f"guardrails_logs collection created",style="bold green")
        
        # cicd_logs collection
        if 'cicd_logs' not in collections:
            db.create_collection('cicd_logs')
            console.print(f"cicd_logs collection created",style="bold green")
        
        # codebase_context collection ( for RAG )
        if 'codebase_context' not in collections:
            db.create_collection('codebase_context')
            console.print(f"codebase_context collection created",style="bold green")
        
        # open_source_context collection ( for RAG )
        if 'open_source_context' not in collections:
            db.create_collection('open_source_context')
            console.print(f"open_source_context collection created",style="bold green")
        
        console.print(f"collections created",style="bold green")
        console.print(f"list of collections: {db.list_collection_names()}",style="bold green")
    except Exception as e:
        console = Console()
        console.print(f"error creating collections and documents: {e}",style="bold red")


if __name__=="__main__":
    # create_db_and_tables()
    parser = argparse.ArgumentParser()
    parser.add_argument("--dev", action="store_true", default=False, help="Run in development environment")
    args = parser.parse_args()
    if args.dev:
        mongo_db_create_collections_and_documents(dev_environment=True, db_name="new_devsecshield_backend_server_db")
    else:
        mongo_db_create_collections_and_documents(dev_environment=False, db_name="new_devsecshield_backend_server_db")