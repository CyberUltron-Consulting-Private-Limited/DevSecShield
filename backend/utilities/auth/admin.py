from backend.utilities.auth.auth_utils import get_hashed_password
from backend.models import User
from sqlmodel import Session, select
from backend.get_db import engine

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