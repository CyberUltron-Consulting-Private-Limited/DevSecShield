import os
import datetime
from typing import Annotated
from .auth_utils import get_hashed_password, get_user_from_header_or_raise_exception
from fastapi import Depends, FastAPI, HTTPException, Header, Request
from sqlmodel import Session, SQLModel, create_engine
from starlette.responses import JSONResponse
from .models import *
from .api_routes.routing_admin import admin_routes
from .api_routes.routing_auth import auth_api_routes
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from fastapi_throttle import RateLimiter
from dotenv import load_dotenv
import psycopg2

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
# sqlite_file_name = os.path.join(os.path.dirname(__file__),"database.db")
# sqlite_url = f"sqlite:///{sqlite_file_name}"
# db_url = sqlite_url

# creating the PostgreSQL database url
load_dotenv()
postgres_url = os.environ['DATABASE_URL']
db_url = postgres_url

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


@app.get("/overview",dependencies=[Depends(limiter)])
async def overview(Authorization: Annotated[str | None, Header()] = None):
    try:
        # authenticating
        user = await get_user_from_header_or_raise_exception(engine,Authorization)
        user_id=user.id

        response_data = [ ]
        # fetching the data
        with Session(engine) as session:
            normal_system_scan = session.exec(select(NormalSystemTM).where(NormalSystemTM.user_id == user_id).order_by(NormalSystemTM.created_at.desc())).all()
            llm_scan = session.exec(select(LLMScan).where(LLMScan.user_id == user_id).order_by(LLMScan.created_at.desc())).all()
            mcp_scan = session.exec(select(MCPScan).where(MCPScan.user_id == user_id).order_by(MCPScan.created_at.desc())).all()
            for proj in normal_system_scan:
                if proj.system_name is not None:
                    response_data.append({
                        "id":"N"+str(proj.id),
                        "type":"normal_system",
                        "name":proj.system_name,
                        "status":proj.status,
                        "created_at":proj.created_at.strftime("%Y-%m-%d")
                    })
            for proj in llm_scan:
                response_data.append({
                    "id":"L"+str(proj.id),
                    "type":"llm_scan",
                    "name":proj.model_name,
                    "status":proj.status,
                    "created_at":proj.created_at.strftime("%Y-%m-%d")
                })
            for proj in mcp_scan:
                response_data.append({
                    "id":"M"+str(proj.id),
                    "type":"mcp_scan",
                    "name":proj.repo.split("/")[-2]+"_"+proj.repo.split("/")[-1].replace(".git",""),
                    "status":proj.status,
                    "created_at":proj.created_at.strftime("%Y-%m-%d")
                })
            return response_data
    except Exception as e:
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        if isinstance(e,HTTPException):
            raise e
        print(f"🟥 Error in overview: {e}")
        raise HTTPException(status_code=400, detail="An error occurred while fetching the overview, please try again later")
    
@app.get("/testing",dependencies=[Depends(limiter)])
async def testing(Authorization: Annotated[str | None, Header()] = None):
    raise HTTPException(status_code=403, detail="Testing")


    
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
    # create_db_and_tables()
    create_user()
    # make_admin()
