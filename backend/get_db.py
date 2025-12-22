import os
from sqlmodel import create_engine
from dotenv import load_dotenv
from fastapi import HTTPException, status
from rich.console import Console

def get_db(dev_environment : bool = False):

    console = Console()
    try:
        if dev_environment:
            sqlite_file_name = os.path.join(os.path.dirname(__file__),"database.db")
            sqlite_url = f"sqlite:///{sqlite_file_name}"
            db_url = sqlite_url
        else:
            load_dotenv()
            postgres_url = os.environ['DATABASE_URL']
            db_url = postgres_url

        engine = create_engine(db_url)
        return engine

    except Exception as e:
        console.print(f"Error getting database: {e}", style="bold red")
        raise e 