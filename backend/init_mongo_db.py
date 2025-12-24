import os
from sqlmodel import SQLModel, create_engine
from pymongo import MongoClient
from rich.console import Console
from .models import *



# def create_db_and_tables():
#     try:
#         console = Console()
#         # creating the SQL engine to communicate to the db
#         sqlite_file_name = os.path.join(os.path.dirname(__file__),"database.db")
#         sqlite_url = f"sqlite:///{sqlite_file_name}"
#         db_url = sqlite_url

#         # creating the PostgreSQL database url
#         # load_dotenv()
#         # postgres_url = os.environ['DATABASE_URL']
#         # db_url = postgres_url

#         engine = create_engine(db_url)
#         SQLModel.metadata.create_all(engine)
#         console.print(f"main database tables created",style="bold green")
#     except Exception as e:
#         console = Console()
#         console.print(f"error creating tables: {e}",style="bold red")

def mongo_db_create_collections_and_documents():
    try:
        # mongo_url = f"mongodb://{os.environ['MONGO_USERNAME']}:{os.environ['MONGO_PASSWORD']}@{os.environ['MONGO_HOST']}:{os.environ['MONGO_PORT']}"
        mongo_url = "mongodb://localhost:27017/"
        # mongo_url = "mongodb://Nikhil:testing123@localhost:27018/"
        mongo_client = MongoClient(mongo_url)
        db = mongo_client['devsecshield_backend_server_db']
        collections = db.list_collection_names()
        console = Console()
        console.print(f"collections: {collections}",style="bold green")

        # conversations collection
        if 'conversations' not in collections:
            db.create_collection('conversations')
            console.print(f"conversations collection created",style="bold green")

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
        
        console.print(f"collections created",style="bold green")
        console.print(f"list of collections: {db.list_collection_names()}",style="bold green")
    except Exception as e:
        console = Console()
        console.print(f"error creating collections and documents: {e}",style="bold red")


if __name__=="__main__":
    # create_db_and_tables()
    mongo_db_create_collections_and_documents()