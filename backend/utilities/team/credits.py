from rich.console import Console
from fastapi import HTTPException, status
from backend.new_models import Team, Scan
from sqlmodel import Session, select 
from backend.get_db import get_db
console = Console()

def check_if_team_has_enough_credits(
    team_id: int,
    credits_required: float,
    team_object: Team | None = None, # if None , get the team object from the database
    ) -> bool:
    """
    Check if a team has enough credits for a scan.
    Arguments :
    - team_id : int
    - scan_type : str
    Returns :
    - bool
    """
    try:
        if team_object:
            return team_object.credit_balance >= credits_required
        
        engine = get_db()
        with Session(engine) as session:
            team = session.exec(select(Team).where(Team.id == team_id)).first()
            if not team:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
            return team.credit_balance >= credits_required
            
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in checking if team has enough credits: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in checking if team has enough credits, please try again later")

def deduct_credits_from_team(
    team_id: int, 
    credits: int,
    team_object: Team | None = None, # if None , get the team object from the database , if provided return the same object after update 
    ) -> Team | None:
    """
    Deduct credits from a team.
    Arguments :
    - team_id : int
    - credits : int
    Returns :
    - Team | None
    Raises :
    - HTTPException : 404 if team not found
    - HTTPException : 500 if error in deducting credits from team
    """
    try:
        if team_object:
            team_object.credit_balance -= credits
            return team_object

        engine = get_db()
        
        with Session(engine) as session:
            team = session.exec(select(Team).where(Team.id == team_id)).first()
            if not team:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
            
            original_credit_balance = team.credit_balance
            new_credit_balance = team.credit_balance - credits
            team.credit_balance = new_credit_balance
            session.add(team)
            session.commit()
            session.refresh(team)

            if credits > 0 and team.credit_balance == original_credit_balance:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in deducting credits from team, please try again later")
            console.print(f"{credits} credits 🪙 deducted from team {team_id} : {original_credit_balance} -> {new_credit_balance}",style="bold yellow2")
            return team

        
    except HTTPException as e:
        console.print(f"HTTPException in deduct_credits_from_team: {e}",style="bold red")
        raise e
    except Exception as e:
        console.print(f"Error in deduct_credits_from_team: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in deducting credits from team, please try again later")


def deduct_credits_from_team_for_message(
    team_id: int,
    team_object: Team | None = None, # if None , get the team object from the database , if provided return the same object after update 
    ) -> Team | None:
    """
    Deduct credits from a team for a message.
    Arguments :
    - team_id : int
    Returns :
    - Team | None
    Raises :
    - HTTPException : 404 if team not found
    - HTTPException : 500 if error in deducting credits from team for message
    """
    try:
        credit_deduction = 0.006
        return deduct_credits_from_team(team_id, credit_deduction)
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in deduct_credits_from_team_for_message: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in deducting credits from team for message, please try again later")

        

def check_if_team_has_enough_credits(
    team_id: int, 
    credits_required: float,
    team_object: Team | None = None, # if None , get the team object from the database
    ) -> bool:
    """
    Check if a team has enough credits.
    Arguments :
    - team_id : int
    - credits : int
    Returns :
    - bool
    """
    try:
        if team_object:
            return team_object.credit_balance >= credits_required

        engine = get_db()
        with Session(engine) as session:
            team = session.exec(select(Team).where(Team.id == team_id)).first()
            if not team:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
            return team.credit_balance >= credits_required
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in checking if team has enough credits: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in checking if team has enough credits, please try again later")


def update_scan_credit_consumed(
    scan_id: int,
    credits_consumed: float,
    scan_object: Scan | None = None, # if None , get the scan object from the database , if provided return the same object after update 
    ) -> Scan | None:
    """
    Update the credit consumed for a scan.
    Arguments :
    - scan_id : int
    - credits_consumed : float
    Returns :
    - Scan | None
    """
    try:
        if scan_object:
            scan_object.credit_consumed = credits_consumed
            return scan_object
        
        engine = get_db()
        with Session(engine) as session:
            scan = session.exec(select(Scan).where(Scan.id == scan_id)).first()
            if not scan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
            console.print(f"Scan : {scan}")
            scan.credit_consumed = credits_consumed
            session.add(scan)
            session.commit()
            session.refresh(scan)
            if scan.credit_consumed != credits_consumed:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in updating scan credit consumed, please try again later")
            return scan

            
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in updating scan credit consumed: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in Estimating credits for scan, please try again later")