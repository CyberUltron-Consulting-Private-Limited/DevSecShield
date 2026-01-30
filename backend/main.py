
import os
from rich.console import Console
from backend.api_routes.routing_scan import scan_routes
from backend.auth_utils.auth_utils import get_hashed_password
from fastapi import FastAPI
from sqlmodel import Session, select
from backend.models import *
from backend.api_routes.routing_admin import admin_routes
from backend.api_routes.routing_auth import auth_api_routes
from backend.api_routes.routing_guardrails import guardrails_routes
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from fastapi_throttle import RateLimiter
from backend.get_db import get_db , get_mongo_client_db
from backend.api_routes.gurardrails_api import guardrails_api_routes
from backend.api_routes.routing_cicd import cicd_routes
from backend.routers.auth import router as auth_router
from backend.routers.scans import router as scans_router
from backend.routers.guardrails import router as guardrails_router
from backend.routers.cicd import router as cicd_router
from backend.routers.guardrails_public import router as guardrails_public_router
from backend.routers.admin import router as admin_router
# Origins for CORS ( not enabled yet )
# origins = [
#     "http://localhost:3000",
#     "https://threatshield.zeroshield.ai",
#     "http://13.203.233.15:3000",
#     "13.203.233.15:3000",
# ]

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

# setting the environment variable to False for local development
os.environ["IS_DOCKER_CONTAINER"] = "False"  # ⚠️⚠️⚠️⚠️⚠️⚠️⚠️
engine = get_db(dev_environment=True)
mongo_client_db = get_mongo_client_db(dev_environment=True)

BASE_MEDIA_PATH = "uploads\\"

# auth_api_routes(app,engine)
# admin_routes(app,engine)  # enable later 
# scan_routes(app,engine,mongo_client_db)
# guardrails_routes(app,engine,mongo_client_db)
# guardrails_api_routes(app,engine,mongo_client_db)
# cicd_routes(app,engine,mongo_client_db)


app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(guardrails_router)
app.include_router(cicd_router)
app.include_router(guardrails_public_router)
app.include_router(admin_router)
    
if __name__=="__main__":

    Console().print("Ran main.py ✔️",style="bold green")
