import os
from pymongo import MongoClient
from sqlmodel import create_engine
from dotenv import load_dotenv
from fastapi import HTTPException, status
from rich.console import Console

def get_db(dev_environment : bool = False):

    console = Console()
    load_dotenv()
    is_docker_container = os.getenv("IS_DOCKER_CONTAINER")
    console.print(f"Is docker container: {is_docker_container}", style="bold green")
    try:
        if is_docker_container and is_docker_container == "True":
            postgres_username = os.environ['PG_USER']
            postgres_password = os.environ['PG_USER_PASS']
            postgres_host = "13.203.233.15"
            postgres_port = "5433"
            postgres_db = os.environ['PG_DB']
            postgres_url = f"postgresql://{postgres_username}:{postgres_password}@{postgres_host}:{postgres_port}/{postgres_db}"
            db_url = postgres_url

        elif dev_environment:
            # sqlite_file_name = "C:\\Users\\HP\\Desktop\\DevSecShield\\backend\\database.db"
            sqlite_file_name = "C:\\Users\\HP\\Desktop\\DevSecShield\\backend\\new_database.db"
            sqlite_url = f"sqlite:///{sqlite_file_name}"
            db_url = sqlite_url
        else:
            postgres_username = os.environ['PG_USER']
            postgres_password = os.environ['PG_USER_PASS']
            postgres_host = "13.203.233.15"
            postgres_port = "5433"
            postgres_db = os.environ['PG_DB']
            postgres_url = f"postgresql://{postgres_username}:{postgres_password}@{postgres_host}:{postgres_port}/{postgres_db}"
            db_url = postgres_url

        engine = create_engine(db_url)
        return engine

    except Exception as e:
        console.print(f"Error getting database: {e}", style="bold red")
        raise e 

def get_mongo_client_db(dev_environment : bool = False):
    load_dotenv()
    is_docker_container = os.getenv("IS_DOCKER_CONTAINER")
    
    if is_docker_container and is_docker_container == "True":
        mongo_username = os.environ['MONGO_INITDB_ROOT_USERNAME']
        mongo_password = os.environ['MONGO_INITDB_ROOT_PASSWORD']
        mongo_host = "13.203.233.15"
        mongo_port = "27017"    
        mongo_url = f"mongodb://{mongo_username}:{mongo_password}@{mongo_host}:{mongo_port}/"
    elif dev_environment:
        mongo_url = "mongodb://localhost:27017/"
    else:
        mongo_username = os.environ['MONGO_INITDB_ROOT_USERNAME']
        mongo_password = os.environ['MONGO_INITDB_ROOT_PASSWORD']
        mongo_host = "13.203.233.15"
        mongo_port = "27017"
        mongo_url = f"mongodb://{mongo_username}:{mongo_password}@{mongo_host}:{mongo_port}/"
    
    mongo_client = MongoClient(mongo_url)
    # db = mongo_client['devsecshield_backend_server_db']
    db = mongo_client['new_devsecshield_backend_server_db']
    return db