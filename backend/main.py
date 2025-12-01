import os
import datetime
from typing import Annotated
from backend.auth_utils.auth_utils import get_hashed_password, get_user_from_header_or_raise_exception
from fastapi import Depends, FastAPI, HTTPException, Header, Request
from sqlmodel import Session, SQLModel, create_engine
from starlette.responses import JSONResponse
from backend.models import *
from backend.api_routes.routing_admin import admin_routes
from backend.api_routes.routing_auth import auth_api_routes
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from fastapi_throttle import RateLimiter
from dotenv import load_dotenv
import psycopg2

from backend.api_routes.routing_dast import dast_routes
from backend.api_routes.routing_discovery import discovery_routes
from backend.api_routes.routing_gitleaks import gitleaks_routes
from backend.api_routes.routing_iac import iac_routes
from backend.api_routes.routing_mcp import mcp_routes
from backend.api_routes.routing_sast import sast_routes
from backend.api_routes.routing_sca_sbom import sca_sbom_routes
from backend.api_routes.routing_llm import llm_routes


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

# creating the SQL engine to communicate to the db
sqlite_file_name = os.path.join(os.path.dirname(__file__),"database.db")
sqlite_url = f"sqlite:///{sqlite_file_name}"
db_url = sqlite_url

# creating the PostgreSQL database url
# load_dotenv()
# postgres_url = os.environ['DATABASE_URL']
# db_url = postgres_url

engine = create_engine(db_url)

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

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)



BASE_MEDIA_PATH = "uploads\\"

auth_api_routes(app,engine)
admin_routes(app,engine)
discovery_routes(app,engine)
sast_routes(app,engine)
dast_routes(app,engine)
iac_routes(app,engine)
sca_sbom_routes(app,engine)
gitleaks_routes(app,engine)
llm_routes(app,engine)
mcp_routes(app,engine)


    
def test_db():
    with Session(engine) as session:
        # user = session.exec(select(User).where(User.email == "nikhil@cyberultron.com")).first()
        # print(user.email)
        # print(user.is_superuser)
        # print(user.password==get_hashed_password("Testing123"))
        all_users = session.exec(select(User).where(User.email == "nikhil@cyberultron.com")).all()
        for user in all_users:
            session.delete(user)
        session.commit()
        print("Users deleted")

    
if __name__=="__main__":
    # test_db()
    create_db_and_tables()
    # create_user()
    # make_admin()
