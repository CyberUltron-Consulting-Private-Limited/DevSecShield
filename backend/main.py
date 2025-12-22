import os
import datetime
from typing import Annotated

from celery import Celery
from rich.console import Console
from backend.api_routes.routing_scan import scan_routes
from backend.auth_utils.auth_utils import get_hashed_password, get_user_from_header_or_raise_exception
from fastapi import Depends, FastAPI, HTTPException, Header, Request
from sqlmodel import Session, SQLModel, create_engine
from starlette.responses import JSONResponse
from backend.models import *
from backend.api_routes.routing_admin import admin_routes
from backend.api_routes.routing_auth import auth_api_routes
from backend.api_routes.routing_guardrails import guardrails_routes
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from fastapi_throttle import RateLimiter
from dotenv import load_dotenv
import psycopg2
from pymongo import MongoClient
from backend.get_db import get_db
from backend.api_routes.gurardrails_api import guardrails_api_routes


#fast api app

# Origins for CORS ( not enabled yet )
origins = [
    "http://localhost:3000",
    "https://threatshield.zeroshield.ai",
    "http://13.203.233.15:3000",
    "13.203.233.15:3000",
]

app = FastAPI(middleware=[
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],  # consider restricting to ["http://localhost:3000"] in dev
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
])

# Limit to 5 requests per minute
limiter = RateLimiter(times=20, seconds=30)

engine = get_db(dev_environment=True)

def create_user():
    with Session(engine) as session:
        test_user = User(first_name="Test",
                         last_name="Nikhil",
                         password=get_hashed_password("Testing123"),
                         email="nikhil@cyberultron.com",
                         is_superuser=True)
        session.add(test_user)  
        session.commit()
def make_admin():
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == "nikhil@cyberultron.com")).first()
        user.is_superuser = True
        session.add(user)
        session.commit()


def get_mongo_client_db():
    mongo_url = "mongodb://localhost:27017/"
    mongo_client = MongoClient(mongo_url)
    db = mongo_client['devsecshield_backend_server_db']
    return db





BASE_MEDIA_PATH = "uploads\\"

auth_api_routes(app,engine)
admin_routes(app,engine)


scan_routes(app,engine,get_mongo_client_db())
guardrails_routes(app,engine,get_mongo_client_db())
guardrails_api_routes(app,engine,get_mongo_client_db())


    
if __name__=="__main__":

    Console().print("Ran main.py ✔️",style="bold green")
