from rich.console import Console
from fastapi import HTTPException, status
from backend.new_models import Team, Scan
from sqlmodel import Session, select
from sqlalchemy import update as sa_update
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
    credits: float,
    team_object: Team | None = None, # DEPRECATED: This parameter is ignored for security (atomic deduction always uses DB)
    ) -> Team | None:
    """
    Deduct credits from a team using ATOMIC database operation.
    
    SECURITY: Always uses atomic UPDATE...WHERE to prevent race conditions.
    The team_object parameter is deprecated and ignored.
    
    Arguments :
    - team_id : int
    - credits : float
    Returns :
    - Team | None
    Raises :
    - HTTPException : 404 if team not found
    - HTTPException : 400 if insufficient credits
    - HTTPException : 500 if error in deducting credits
    """
    try:
        # SECURITY FIX: Always use atomic database operation, never in-memory modification
        # The team_object parameter is intentionally ignored to prevent race conditions
        
        engine = get_db()
        
        with Session(engine) as session:
            # Atomic deduction: UPDATE ... WHERE balance >= credits (prevents race condition)
            result = session.exec(
                sa_update(Team)
                .where(Team.id == team_id, Team.credit_balance >= credits)
                .values(credit_balance=Team.credit_balance - credits)
            )
            session.commit()
            
            if result.rowcount == 0:
                # Either team not found or insufficient balance
                team = session.exec(select(Team).where(Team.id == team_id)).first()
                if not team:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Insufficient credits")
            
            team = session.exec(select(Team).where(Team.id == team_id)).first()
            console.print(f"{credits} credits 🪙 deducted from team {team_id} : {team.credit_balance + credits:.4f} -> {team.credit_balance:.4f}",style="bold yellow2")
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


def refund_credits_to_team(
    team_id: int,
    credits: float,
    ) -> Team | None:
    """
    Refund credits to a team (used when scan dispatch fails after deduction).
    
    SECURITY: Uses atomic database operation.
    
    Arguments :
    - team_id : int
    - credits : float (amount to refund)
    Returns :
    - Team | None
    Raises :
    - HTTPException : 404 if team not found
    - HTTPException : 500 if error in refunding credits
    """
    try:
        engine = get_db()
        
        with Session(engine) as session:
            # Atomic addition: UPDATE ... WHERE team_id = X
            result = session.exec(
                sa_update(Team)
                .where(Team.id == team_id)
                .values(credit_balance=Team.credit_balance + credits)
            )
            session.commit()
            
            if result.rowcount == 0:
                team = session.exec(select(Team).where(Team.id == team_id)).first()
                if not team:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found for refund")
                # This shouldn't happen - rowcount 0 but team exists
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Refund failed - unknown error")
            
            team = session.exec(select(Team).where(Team.id == team_id)).first()
            console.print(f"{credits} credits 🪙 REFUNDED to team {team_id} : {team.credit_balance - credits:.4f} -> {team.credit_balance:.4f}",style="bold green")
            return team

    except HTTPException as e:
        console.print(f"HTTPException in refund_credits_to_team: {e}",style="bold red")
        raise e
    except Exception as e:
        console.print(f"Error in refund_credits_to_team: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error refunding credits to team, please try again later")


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