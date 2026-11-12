import os
import time

from pymongo import MongoClient
from sqlalchemy.pool import QueuePool
from sqlmodel import create_engine
from dotenv import load_dotenv
from fastapi import HTTPException, status
from rich.console import Console

_console = Console()
load_dotenv()

_is_docker = os.getenv("IS_DOCKER_CONTAINER", "False") == "True"

# Hosts: Docker uses container names on the shared network, local uses localhost with host-mapped ports
PG_HOST = os.getenv("PG_HOST", "devsecshield-postgres" if _is_docker else "localhost")
PG_PORT = os.getenv("PG_PORT", "5432" if _is_docker else "4433")
MONGO_HOST = os.getenv("MONGO_HOST", "devsecshield-mongodb" if _is_docker else "localhost")
MONGO_PORT = os.getenv("MONGO_PORT", "27017")

# Singleton instances for connection pooling
_pg_engine = None
_mongo_db = None


def _pool_setting(name: str, default: int, low: int, high: int) -> int:
    raw = os.getenv(name, "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError:
        value = default
    return value if low <= value <= high else default


def pool_settings() -> dict:
    """Connection pool per process, from the environment (F1.1, DA E2).  Every gunicorn worker and every other process
    (cloud worker, DAST scheduler, celery) opens its own pool, so the sum across processes plus a reserve must stay
    below PostgreSQL ``max_connections`` (staging: 100).  Defaults keep the previous 10 + 20."""
    return {"pool_size": _pool_setting("DB_POOL_SIZE", 10, 1, 500),
            "max_overflow": _pool_setting("DB_MAX_OVERFLOW", 20, 0, 500),
            "pool_timeout": _pool_setting("DB_POOL_TIMEOUT", 30, 1, 600)}


class TimedQueuePool(QueuePool):
    """QueuePool that adds the time each checkout took (waiting, connecting, pre-ping) to the current node request's
    timing (``Server-Timing: pool;dur=``).  A no-op outside a node request."""

    def connect(self):  # type: ignore[override]
        from backend.utilities.request_timing import add_pool_wait

        t0 = time.perf_counter()
        try:
            return super().connect()
        finally:
            add_pool_wait(time.perf_counter() - t0)


def get_db():

    global _pg_engine
    console = _console
    try:
        if _pg_engine is not None:
            return _pg_engine
        postgres_username = os.environ['PG_USER']
        postgres_password = os.environ['PG_USER_PASS']
        postgres_db = os.environ['PG_DB']
        postgres_url = f"postgresql://{postgres_username}:{postgres_password}@{PG_HOST}:{PG_PORT}/{postgres_db}"

        # hide_parameters: SQL errors in logs never include bound values (credentials, configs).
        _pg_engine = create_engine(postgres_url, poolclass=TimedQueuePool, **pool_settings(), pool_pre_ping=True,
                                   hide_parameters=True)
        return _pg_engine

    except Exception as e:
        console.print(f"Error getting database: connection to {PG_HOST}:{PG_PORT} failed", style="bold red")
        raise e 

def get_mongo_client_db():
    global _mongo_db
    mongo_username = os.getenv('MONGO_INITDB_ROOT_USERNAME')
    mongo_password = os.getenv('MONGO_INITDB_ROOT_PASSWORD')
    
    if _mongo_db is not None:
        return _mongo_db
    
    if mongo_username and mongo_password:
        mongo_url = f"mongodb://{mongo_username}:{mongo_password}@{MONGO_HOST}:{MONGO_PORT}/"
    else:
        mongo_url = f"mongodb://{MONGO_HOST}:{MONGO_PORT}/"
    
    mongo_client = MongoClient(mongo_url, maxPoolSize=50, minPoolSize=5)
    _mongo_db = mongo_client['new_devsecshield_backend_server_db']
    return _mongo_db