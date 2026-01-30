from rich.console import Console
from fastapi import HTTPException, status
from backend.new_models import Team, Scan
console = Console()

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
        #TODO : Implement this function
        pass
    except HTTPException as e:
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
        #TODO : Implement this function
        pass
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
        #TODO : Implement this function
        pass
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
        #TODO : Implement this function
        pass
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in updating scan credit consumed: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in updating scan credit consumed, please try again later")