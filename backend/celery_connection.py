from celery import Celery
from dotenv import load_dotenv
from rich.console import Console
import os

def get_celery_app():
    console = Console()
    load_dotenv()
    username = os.getenv("RABBIT_ADMIN_USERNAME")
    password = os.getenv("RABBIT_ADMIN_PASSWORD")
    mongo_url = os.getenv("RABBIT_MONGO_CONNECTION_URL")
    if not username or not password or not mongo_url:
        console.print(f"Username, password or mongo url not set",style="bold red")
        return None
    simple_app = Celery('task_sender',
                    broker=f"amqp://{username}:{password}@localhost:5672",
                    backend=mongo_url)
    return simple_app