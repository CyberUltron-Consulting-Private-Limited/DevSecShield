import os
from sqlmodel import SQLModel, create_engine
from pymongo import MongoClient
from rich.console import Console
from backend.models import *
import argparse
from dotenv import load_dotenv



def create_db_and_tables():
    try:
        console = Console()
        # creating the SQL engine to communicate to the db
        sqlite_file_name = os.path.join(os.path.dirname(__file__),"database.db")
        sqlite_url = f"sqlite:///{sqlite_file_name}"
        db_url = sqlite_url


        engine = create_engine(db_url)
        SQLModel.metadata.create_all(engine)
        console.print(f"main database tables created",style="bold green")
    except Exception as e:
        console = Console()
        console.print(f"error creating tables: {e}",style="bold red")


if __name__ == "__main__":
    create_db_and_tables()