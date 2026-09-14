from fastapi import APIRouter, Depends, Header, HTTPException, status
from typing import Annotated
from rich.console import Console
from fastapi_throttle import RateLimiter
from backend.utilities.db.schemas import CreateTeamData , UpdateTeamData , RemoveOrAddMembersToTeamData
from backend.utilities.team.validation import check_if_user_is_in_team , check_if_user_is_admin_of_team
from backend.utilities.auth.auth_utils import get_user_from_header_or_raise_exception
from backend.get_db import get_db , get_mongo_client_db
from sqlmodel import Session, select
from backend.new_models import Team, TeamMembership , User , Scan , CicdIntegration , GuardrailsIntegration
from backend.utilities.team.membership import add_emails_to_team , remove_emails_from_team
from sqlalchemy import or_
from backend.utilities.dashboard.team import generate_team_dashboard_data , generate_team_list_dashboard_data
from backend.utilities.db.encryption import prepare_secret_for_storage, SECRET_PLACEHOLDER
import copy

router = APIRouter( tags=["team"] )   
console = Console()
limiter = RateLimiter(times=20, seconds=30) # 20 requests per 30 seconds
MAX_TEAMS_PER_USER = 5 # maximum number of teams a user can create


# new ✅
@router.get("/team/{team_id}",summary="Get the team details")
async def get_team(
    team_id: int,
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)]):
    """
    Get the team details
    """
    try:
        # STEP [ 0 ] : =========== Get the engine and user ======================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes
        
        # STEP [ 1 ] : =========== Check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)

        # STEP [ 2 ] : =========== get the team details from the main db ======================
        team = None 
        is_team_admin = False
        with Session(engine) as session:
            team = session.exec(select(Team).where(Team.id == team_id)).first()
            if team == None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
            console.print(f"Team with id: {team_id} found", style="dim green")
            
            #---------------------> check if user is team admin
            for membership in team.team_memberships:
                if membership.user.email == user.email and membership.role == "admin":
                    is_team_admin = True
                    break
        


            # STEP [ 3 ] : =========== return the team details ======================
            # SECURITY: Mask sensitive credentials in response
            safe_integration_settings = None
            if team.integration_settings:
                safe_integration_settings = copy.deepcopy(team.integration_settings)
                if "jira" in safe_integration_settings and safe_integration_settings["jira"]:
                    if "api_token" in safe_integration_settings["jira"] and safe_integration_settings["jira"]["api_token"]:
                        # Mask the token - show only that it's configured
                        safe_integration_settings["jira"]["api_token"] = SECRET_PLACEHOLDER if safe_integration_settings["jira"]["api_token"] else None
            
            return {
                "team_id": team.id,
                "team_name": team.name,
                "team_description": team.description,
                "is_team_admin": is_team_admin,
                "team_members": [{"email": member.user.email, "role": member.role} for member in team.team_memberships],
                "team_created_at": team.created_at,
                "team_credit_balance":  round(float(team.credit_balance), 2) if team.credit_balance else None,
                "team_integration_settings": safe_integration_settings,
                "team_settings": team.settings,
            }
        

    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in getting team details: {e}", style="red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error in getting team details: {e}")


# new ✅
@router.get("/teams",summary="List all teams that the current user is a member of")
async def list_teams(
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)]):
    """
    List all teams
    """
    try:
        # STEP [ 1 ] : =========== Get the engine and user ======================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes

        
        # STEP [ 2 ] : =========== get the teams from the main db ======================
        teams = []
        with Session(engine) as session:

            user = session.exec(select(User).where(User.id == user.id)).first()
            
            or_statements = []
            for membership in user.team_memberships:
                or_statements.append(Team.id == membership.team_id)
            team_objects = session.exec(select(Team).where(or_(*or_statements))).all()
            for team_object in team_objects:
                teams.append({
                    "team_id": team_object.id,
                    "team_name": team_object.name,
                    "team_description": team_object.description,
                    "team_members": [member.user.email for member in team_object.team_memberships],
                    "team_created_at": team_object.created_at,
                    "team_credit_balance": round(float(team_object.credit_balance), 2) if team_object.credit_balance else None,
                })
        

        # STEP [ 3 ] : =========== return the teams ======================
        return teams
        
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in listing teams: {e}", style="red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error in listing teams: {e}")



# new ✅
@router.post("/team",summary="Create a new team")
async def create_team(
    data: CreateTeamData,
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)]):
    """
    Create a new team
    """
    try:
        # STEP [ 1 ] : =========== Get the engine and user ======================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes

        
        # STEP [ 2 ] : =========== create the team in the main db ======================
        with Session(engine) as session:
            team = Team(
                name=data.name, 
                description=data.description,
            )
            user = session.exec(select(User).where(User.id == user.id)).first()
            if user == None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
            if len(user.team_memberships) >= MAX_TEAMS_PER_USER:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Maximum number of teams reached")
            membership = TeamMembership(user=user, team=team, role="admin")
            session.add(membership)
            session.commit()

            # STEP [ 3 ] : =========== return the team details ======================
            return {
                "team_id": team.id,
                "team_name": team.name,
                "team_description": team.description,
                "team_members": [member.user.email for member in team.team_memberships],
            }

    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in creating team: {e}", style="red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error in creating team: {e}")


# new ✅
@router.put("/team/{team_id}",summary="Update the team details")
async def update_team(
    team_id: int,
    data: UpdateTeamData,
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)]):
    """
    Update the team details
    """
    try:
        # STEP [ 1 ] : =========== Get the engine and user ======================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes
        
        # STEP [ 2 ] : =========== check if user is admin of team ======================
        check_if_user_is_admin_of_team(user.id, team_id, engine)

        # STEP [ 3 ] : =========== update the team in the main db ======================
        with Session(engine) as session:
            team = session.exec(select(Team).where(Team.id == team_id)).first()
            if team == None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
            team.name = data.name
            team.description = data.description
            if data.integration_settings is not None:
                if data.integration_settings.jira is not None:
                    specific_settings_dict = data.integration_settings.model_dump()
                    settings_dict = (team.integration_settings or {}).copy()
                    
                    # Encrypt the token; if the UI echoed the masked placeholder, keep the stored ciphertext.
                    jira_settings = specific_settings_dict["jira"]
                    if jira_settings:
                        existing_token = (settings_dict.get("jira") or {}).get("api_token")
                        jira_settings["api_token"] = prepare_secret_for_storage(
                            jira_settings.get("api_token"),
                            existing_token,
                        )
                    settings_dict["jira"] = jira_settings
                    team.integration_settings = settings_dict
            session.add(team)
            session.commit()

    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in updating team: {e}", style="red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error in updating team: {e}")


# new ✅
@router.patch("/team/{team_id}",summary="Remove or Add members to the team")
async def remove_or_add_members_to_team(
    team_id: int,
    data: RemoveOrAddMembersToTeamData,
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)]):
    """
    Remove or Add members to the team using a list of email ids
    """
    try:
        # STEP [ 1 ] : =========== Get the engine and user ======================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes
        
        # STEP [ 2 ] : =========== check if user is admin of team ======================
        check_if_user_is_admin_of_team(user.id, team_id, engine)

        # STEP [ 3 ] : =========== remove or add members to the team ======================
        if data.intent == "remove":
            await remove_emails_from_team(data.email_ids, team_id, engine)
        elif data.intent == "add":
            await add_emails_to_team(data.email_ids, team_id, engine)
        

        return {
            "message": f"Members {data.intent}ed to the team",
        }
                
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in removing or adding members to team: {e}", style="red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error in removing or adding members to team: {e}")


# new ✅
@router.delete("/team/{team_id}",summary="Delete a team")
async def delete_team(
    team_id: int,
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)]):
    """
    Delete a team
    """
    try:
        # STEP [ 1 ] : =========== Get the engine and user ======================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        if user.default_team_id == team_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete default team")
        
        # STEP [ 1 ] : =========== check if user is admin of team ======================
        check_if_user_is_admin_of_team(user.id, team_id, engine)



        # STEP [ 3 ] : ======================= Delete all the scans associated with the team ==============================
        scan_ids_list = []
        with Session(engine) as session:
            scans = session.exec(select(Scan).where(Scan.team_id == team_id)).all()
            for scan in scans:
                scan_ids_list.append(scan.id)
                session.delete(scan)
            session.commit()
        console.print(f"Scans with ids: {scan_ids_list} deleted from main database" ,style="bold orange3")


        for scan_id in scan_ids_list:
            # -------------------> Delelte messages log with scan_id -----------------------------
            message_collection = mongo_db["message_log"]
            result = message_collection.delete_many({"scan_id": scan_id})
            console.print(f"{result.deleted_count} Messages with scan_id: {scan_id} deleted from mongo db" ,style="bold orange3")

            # -------------------> Delete active context log with scan_id -----------------------------
            active_context_collection = mongo_db["active_context"]
            result = active_context_collection.delete_many({"scan_id": scan_id})
            console.print(f"{result.deleted_count} Active context with scan_id: {scan_id} deleted from mongo db" ,style="bold orange3")


        # STEP [ 5 ] ======================= Delete cicd integration records associated with the team ==============================
        cicd_ids_list = []
        with Session(engine) as session:
            cicd_integrations = session.exec(select(CicdIntegration).where(CicdIntegration.team_id == team_id)).all()
            for cicd_integration in cicd_integrations:
                cicd_ids_list.append(cicd_integration.id)
                session.delete(cicd_integration)
            session.commit()
        console.print(f"Cicd integrations with ids: {cicd_ids_list} deleted from main database" ,style="bold orange3")


        for cicd_id in cicd_ids_list:
            # -------------------> Delete cicd logs with cicd_id -----------------------------
            cicd_logs_collection = mongo_db["cicd_logs"]
            cicd_logs_collection.delete_many({"ci_cd_integration_id": cicd_id})
            console.print(f"Cicd logs deleted successfully for integration {cicd_id}", style="bold green")

        

        # STEP [ 6 ] ======================= Delete guardrails associated with the team ==============================
        guardrails_ids_list = []
        with Session(engine) as session:
            guardrails = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.team_id == team_id)).all()
            for guardrails_integration in guardrails:
                guardrails_ids_list.append(guardrails_integration.id)
                session.delete(guardrails_integration)
            session.commit()
        console.print(f"Guardrails with ids: {guardrails_ids_list} deleted from main database" ,style="bold orange3")


        for guardrails_id in guardrails_ids_list:
            # -------------------> Delete guardrails logs with guardrails_id -----------------------------
            guardrails_logs_collection = mongo_db["guardrails_logs"]
            guardrails_logs_collection.delete_many({"integration_id": guardrails_id})
            console.print(f"Guardrails logs deleted successfully for integration {guardrails_id}", style="bold green")
        


        

        # STEP [ 2 ] ------------------ Delete team -----------------------------
        with Session(engine) as session:        
            team_memberships = session.exec(select(TeamMembership).where(TeamMembership.team_id == team_id)).all()
            for team_membership in team_memberships:
                session.delete(team_membership)
            session.commit()
    

            #---------------------> deleting team object
            team = session.exec(select(Team).where(Team.id == team_id)).first()
            if team == None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
            session.delete(team)
            session.commit()
        console.print(f"Team with id: {team_id} deleted from main database" ,style="bold orange3")
        

        

    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in deleting team: {e}", style="red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error in deleting team: {e}")


# new ✅
@router.get("/team/{team_id}/dashboard",summary="Get the dashboard data for a team")
async def get_team_dashboard(
    team_id: int,
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)]):
    """
    Get the dashboard data for a team
    """
    try:
        # STEP [ 1 ] : =========== Get the engine and user ======================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)

        # STEP [ 2 ] : =========== check if user is in team ======================
        check_if_user_is_in_team(user.id, team_id, engine)

        # STEP [ 3 ] : =========== get the dashboard data for the team ======================
        dashboard_data = generate_team_dashboard_data(team_id, engine)

        # STEP [ 4 ] : =========== return the dashboard data ======================
        return dashboard_data
    
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in getting team dashboard: {e}", style="red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error in getting team dashboard: {e}")


@router.get("/teams/dashboard",summary="Get the dashboard data for all teams that the current user is a member of")
async def get_teams_dashboard(
    Authorization: Annotated[str | None, Header()] = None , 
    dependencies=[Depends(limiter)]):
    """
    Get the dashboard data for all teams that the current user is a member of
    """
    try:
        # STEP [ 1 ] : =========== Get the engine and user ======================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)

        # STEP [ 2 ] : =========== get the dashboard data for all teams that the current user is a member of ======================
        dashboard_data = generate_team_list_dashboard_data(user.id, engine)

        # STEP [ 3 ] : =========== return the dashboard data ======================
        return dashboard_data
    
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in getting teams dashboard: {e}", style="red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error in getting teams dashboard: {e}")