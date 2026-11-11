from fastapi import APIRouter, Depends, Header, HTTPException, status
from typing import Annotated
from rich.console import Console
from backend.utilities.ratelimit import RateLimiter
from backend.utilities.cbom_sources.cleanup import delete_cbom_sources_for_team
from backend.utilities.db.schemas import CreateTeamData , UpdateTeamData , RemoveOrAddMembersToTeamData
from backend.utilities.team.validation import check_if_user_is_in_team , check_if_user_is_admin_of_team
from backend.utilities.auth.auth_utils import get_user_from_header_or_raise_exception
from backend.get_db import get_db , get_mongo_client_db
from sqlmodel import Session, select
from backend.new_models import Team, TeamMembership , User , Scan , CicdIntegration , GuardrailsIntegration
from backend.utilities.team.membership import add_emails_to_team , remove_emails_from_team
from backend.utilities.team import invitations
from backend.new_models import TeamInvitation
from sqlalchemy import or_
from backend.utilities.dashboard.team import generate_team_dashboard_data , generate_team_list_dashboard_data
from backend.utilities.db.encryption import prepare_secret_for_storage, is_secret_placeholder

router = APIRouter( tags=["team"] )   
console = Console()
# Per verified user, per worker (backend/utilities/ratelimit.py).
read_limiter = RateLimiter("team.read", times=120, seconds=60)
write_limiter = RateLimiter("team.write", times=20, seconds=60)
MAX_TEAMS_PER_USER = 5 # maximum number of teams a user can create


def public_integration_settings(stored: dict | None) -> dict | None:
    """What GET /team shows of the team's integration settings, to every member: the Jira email and URL and
    ``api_token_set`` (true / false).  The token itself never leaves the server, nor does any other stored key."""
    if not isinstance(stored, dict):
        return None
    out: dict = {}
    if "jira" in stored:
        jira = stored.get("jira")
        out["jira"] = None if not isinstance(jira, dict) else {
            "email": jira.get("email"),
            "url": jira.get("url"),
            "api_token_set": bool(jira.get("api_token")),
        }
    return out


# new ✅
@router.get("/team/{team_id}",summary="Get the team details", dependencies=[Depends(read_limiter)])
async def get_team(
    team_id: int,
    Authorization: Annotated[str | None, Header()] = None ):
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
                if membership.user_id == user.id and membership.role == "admin":
                    is_team_admin = True
                    break
        


            # STEP [ 3 ] : =========== return the team details ======================
            # Secrets are write-only: only whether the Jira token is set, never the token (nor a stand-in for it).
            safe_integration_settings = public_integration_settings(team.integration_settings)

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
@router.get("/teams",summary="List all teams that the current user is a member of", dependencies=[Depends(read_limiter)])
async def list_teams(
    Authorization: Annotated[str | None, Header()] = None ):
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
@router.post("/team",summary="Create a new team", dependencies=[Depends(write_limiter)])
async def create_team(
    data: CreateTeamData,
    Authorization: Annotated[str | None, Header()] = None ):
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
@router.put("/team/{team_id}",summary="Update the team details", dependencies=[Depends(write_limiter)])
async def update_team(
    team_id: int,
    data: UpdateTeamData,
    Authorization: Annotated[str | None, Header()] = None ):
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
                if data.integration_settings.jira is None and "jira" in data.integration_settings.model_fields_set:
                    # An explicit "jira": null is the settings page with the three Jira fields emptied: remove the
                    # integration and its stored token. Before, it was ignored and the page still said "Team
                    # updated successfully" while the old values came back on reload.
                    settings_dict = (team.integration_settings or {}).copy()
                    settings_dict["jira"] = None
                    team.integration_settings = settings_dict
                elif data.integration_settings.jira is not None:
                    specific_settings_dict = data.integration_settings.model_dump()
                    settings_dict = (team.integration_settings or {}).copy()
                    
                    # Encrypt the token; if the UI echoed the masked placeholder, keep the stored ciphertext.
                    jira_settings = specific_settings_dict["jira"]
                    if jira_settings:
                        existing = settings_dict.get("jira") or {}
                        existing_token = existing.get("api_token")
                        if is_secret_placeholder(jira_settings.get("api_token")):
                            # an empty token field keeps the stored token, but only for the Jira site and account
                            # it was entered for: it is never sent to a URL or account somebody changed later
                            if not existing_token:
                                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                                    detail="Enter the Jira API token")
                            if (jira_settings.get("url") or "") != (existing.get("url") or "") or \
                                    (jira_settings.get("email") or "") != (existing.get("email") or ""):
                                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                                    detail="Re-enter the Jira API token: the Jira URL or email changed")
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
@router.patch("/team/{team_id}",summary="Remove or Add members to the team", dependencies=[Depends(write_limiter)])
async def remove_or_add_members_to_team(
    team_id: int,
    data: RemoveOrAddMembersToTeamData,
    Authorization: Annotated[str | None, Header()] = None ):
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
            invited = await add_emails_to_team(data.email_ids, team_id, engine, invited_by_user_id=user.id)
            return {"message": f"Invitation sent to {', '.join(invited)}", "invited": invited}

        return {
            "message": "Members removed from the team",
        }
                
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in removing or adding members to team: {e}", style="red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error in removing or adding members to team: {e}")


# new ✅
@router.delete("/team/{team_id}",summary="Delete a team", dependencies=[Depends(write_limiter)])
async def delete_team(
    team_id: int,
    Authorization: Annotated[str | None, Header()] = None ):
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



        # STEP [ 2b ] : ====================== Delete CBOM Sources rows (scan nodes, sources, runs, evidence) =====
        cbom_counts = delete_cbom_sources_for_team(engine, team_id)
        console.print(f"CBOM sources rows deleted for team {team_id}: {cbom_counts}", style="bold orange3")

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
            for invitation in session.exec(select(TeamInvitation).where(TeamInvitation.team_id == team_id)).all():
                session.delete(invitation)
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
@router.get("/team/{team_id}/dashboard",summary="Get the dashboard data for a team", dependencies=[Depends(read_limiter)])
async def get_team_dashboard(
    team_id: int,
    Authorization: Annotated[str | None, Header()] = None ):
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


@router.get("/teams/dashboard",summary="Get the dashboard data for all teams that the current user is a member of", dependencies=[Depends(read_limiter)])
async def get_teams_dashboard(
    Authorization: Annotated[str | None, Header()] = None ):
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

# ------------------------------------------------------------------------------------- invitations (team admins)

@router.get("/team/{team_id}/invitations", summary="Open invitations of the team (admin)", dependencies=[Depends(read_limiter)])
async def list_team_invitations(team_id: int, Authorization: Annotated[str | None, Header()] = None):
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_admin_of_team(user.id, team_id, engine)
    return {"invitations": invitations.list_invitations(team_id, engine)}


@router.post("/team/{team_id}/invitations/{invitation_id}/resend",
             summary="Mail a new invitation link; the previous link stops working (admin)", dependencies=[Depends(write_limiter)])
async def resend_team_invitation(team_id: int, invitation_id: int, Authorization: Annotated[str | None, Header()] = None):
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_admin_of_team(user.id, team_id, engine)
    await invitations.resend_invitation(team_id, invitation_id, user.id, engine)
    return {"message": "A new invitation link was sent"}


@router.delete("/team/{team_id}/invitations/{invitation_id}", summary="Revoke an invitation (admin)",
               dependencies=[Depends(write_limiter)])
async def revoke_team_invitation(team_id: int, invitation_id: int, Authorization: Annotated[str | None, Header()] = None):
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_admin_of_team(user.id, team_id, engine)
    invitations.revoke_invitation(team_id, invitation_id, engine)
    return {"message": "Invitation revoked"}
