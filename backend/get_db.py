import os
from pymongo import MongoClient
from sqlmodel import create_engine
from dotenv import load_dotenv
from fastapi import HTTPException, status
from rich.console import Console

_console = Console()
load_dotenv()

_is_docker = os.getenv("IS_DOCKER_CONTAINER", "False") == "True"

# Hosts: Docker uses production host, local uses env var with localhost default
PG_HOST = os.getenv("PG_HOST", "13.203.233.15" if _is_docker else "localhost")
PG_PORT = os.getenv("PG_PORT", "4433")
MONGO_HOST = os.getenv("MONGO_HOST", "13.203.233.15" if _is_docker else "localhost")
MONGO_PORT = os.getenv("MONGO_PORT", "27017")


def get_db():

    console = _console
    try:
        postgres_username = os.environ['PG_USER']
        postgres_password = os.environ['PG_USER_PASS']
        postgres_db = os.environ['PG_DB']
        postgres_url = f"postgresql://{postgres_username}:{postgres_password}@{PG_HOST}:{PG_PORT}/{postgres_db}"

        console.print(f"Database URL: {postgres_url}", style="bold green")

        engine = create_engine(postgres_url)
        return engine

    except Exception as e:
        console.print(f"Error getting database: {e}", style="bold red")
        raise e 

def get_mongo_client_db():
    mongo_username = os.getenv('MONGO_INITDB_ROOT_USERNAME')
    mongo_password = os.getenv('MONGO_INITDB_ROOT_PASSWORD')
    
    if mongo_username and mongo_password:
        mongo_url = f"mongodb://{mongo_username}:{mongo_password}@{MONGO_HOST}:{MONGO_PORT}/"
    else:
        mongo_url = f"mongodb://{MONGO_HOST}:{MONGO_PORT}/"
    
    mongo_client = MongoClient(mongo_url)
    db = mongo_client['new_devsecshield_backend_server_db']
    return db