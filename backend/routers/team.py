from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from typing import Annotated
from rich.console import Console
from starlette.concurrency import run_in_threadpool
from backend.utilities.ratelimit import RateLimiter
from backend.utilities.cbom_sources.cleanup import delete_cbom_sources_for_team
from backend.utilities.db.schemas import ChangeMemberRoleData, CreateTeamData , UpdateTeamData , RemoveOrAddMembersToTeamData
from backend.utilities.team.validation import check_if_user_is_in_team , check_if_user_is_admin_of_team
from backend.utilities.auth.auth_utils import get_user_from_header_or_raise_exception
from backend.get_db import get_db , get_mongo_client_db
from sqlmodel import Session, select
from backend.new_models import Team, TeamMembership , User , Scan , CicdIntegration , GuardrailsIntegration
from backend.utilities.team.membership import add_emails_to_team
from backend.utilities.team import invitations
from backend.utilities.team import roles as team_roles
from backend.new_models import TeamInvitation
from sqlalchemy import or_
from backend.utilities.dashboard.team import generate_team_dashboard_data , generate_team_list_dashboard_data
from backend.utilities.db.encryption import prepare_secret_for_storage, is_secret_placeholder
from backend.utilities.rbac import audit
from backend.utilities.rbac.permissions import (
    ADMIN_ROLES, DEFAULT_INVITE_ROLE, assignable_roles, invitable_roles, matrix, permissions_for, role_has,
)
from backend.utilities.rbac.policy import Access, request_meta

router = APIRouter( tags=["team"] )
console = Console()
# Per verified user, per worker (backend/utilities/ratelimit.py).
read_limiter = RateLimiter("team.read", times=120, seconds=60)
write_limiter = RateLimiter("team.write", times=20, seconds=60)
MAX_TEAMS_PER_USER = 5 # maximum number of teams a user can create
# Route policies (utilities/rbac): bound to this module's get_db, which the tests replace.
access = Access(lambda: get_db())


def _principal(request: Request):
    """The account the route policy verified (utilities/rbac/policy.py)."""
    return request.state.access.principal


def _record_invites(engine, team_id: int, principal, meta: dict, emails: list[str], role: str,
                    action: str = "team.members.invite") -> bool:
    """One audit event per invited address (the invitations were already stored and mailed)."""
    try:
        with Session(engine) as session:
            for email in emails:
                audit.record(session, action=action, team_id=team_id, object_type="invitation", object_id=email,
                             ip=meta.get("ip"), user_agent=meta.get("user_agent"),
                             details={"email": email, "role": role, "method": meta.get("method")},
                             **audit.actor_fields(principal))
            session.commit()
        return True
    except Exception as exc:
        console.print(f"audit: invitation events not recorded ({type(exc).__name__})", style="red")
        return False


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
@router.get("/team/{team_id}",summary="Get the team details", dependencies=[Depends(read_limiter), access.team("team.read")])
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
        my_role = None
        with Session(engine) as session:
            team = session.exec(select(Team).where(Team.id == team_id)).first()
            if team == None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
            console.print(f"Team with id: {team_id} found", style="dim green")

            #---------------------> the caller's role: what the UI shows and hides (the API refuses anyway)
            for membership in team.team_memberships:
                if membership.user_id == user.id:
                    my_role = membership.role
                    break
            has_owner = any(m.role == "owner" for m in team.team_memberships)


            # STEP [ 3 ] : =========== return the team details ======================
            # Secrets are write-only: only whether the Jira token is set, never the token (nor a stand-in for it).
            safe_integration_settings = public_integration_settings(team.integration_settings)

            return {
                "team_id": team.id,
                "team_name": team.name,
                "team_description": team.description,
                "is_team_admin": my_role in ADMIN_ROLES,
                "role": my_role,
                "permissions": permissions_for(my_role),
                "assignable_roles": list(assignable_roles(my_role)),
                "invitable_roles": [r for r in ("viewer", "member", "admin") if r in invitable_roles(my_role)],
                "has_owner": has_owner,
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
@router.get("/teams",summary="List all teams that the current user is a member of", dependencies=[Depends(read_limiter), access.authenticated()])
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
            my_roles = {membership.team_id: membership.role for membership in user.team_memberships}
            for team_object in team_objects:
                teams.append({
                    "team_id": team_object.id,
                    "team_name": team_object.name,
                    "team_description": team_object.description,
                    "role": my_roles.get(team_object.id),
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
@router.post("/team",summary="Create a new team (the creator owns it)", dependencies=[Depends(write_limiter), access.authenticated()])
async def create_team(
    data: CreateTeamData,
    request: Request,
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
            membership = TeamMembership(user=user, team=team, role="owner")  # the creator owns the team
            session.add(membership)
            session.flush()
            meta = request_meta(request)
            audit.record(session, action="team.create", team_id=team.id, object_type="team", object_id=team.id,
                         ip=meta["ip"], user_agent=meta["user_agent"], details={"name": team.name[:100]},
                         **audit.actor_fields(_principal(request)))
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
@router.put("/team/{team_id}",summary="Update the team details", dependencies=[Depends(write_limiter), access.team("team.update")])
async def update_team(
    team_id: int,
    data: UpdateTeamData,
    request: Request,
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
        if data.integration_settings is not None and not role_has(_principal(request).role, "team.integrations.manage"):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only team admins can change the Jira integration.")

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
@router.patch("/team/{team_id}",summary="Invite people to the team (with a role) or remove members",
              dependencies=[Depends(write_limiter), access.team("team.members.invite")])
async def remove_or_add_members_to_team(
    team_id: int,
    data: RemoveOrAddMembersToTeamData,
    request: Request,
    Authorization: Annotated[str | None, Header()] = None ):
    """
    Invite addresses (``intent: add``, optional ``role``: member by default; admins invite members and viewers,
    owners also admins) or remove members (``intent: remove``: admins remove members and viewers, owners anybody;
    a team keeps one owner; one refused address refuses the whole request).
    """
    try:
        # STEP [ 1 ] : =========== Get the engine and user ======================
        engine = get_db()
        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        # user = User(id=1) # for testing purposes

        # STEP [ 2 ] : =========== check if user is admin of team ======================
        check_if_user_is_admin_of_team(user.id, team_id, engine)
        principal = _principal(request)
        meta = request_meta(request)

        # STEP [ 3 ] : =========== remove or add members to the team ======================
        if data.intent == "remove":
            if not role_has(principal.role, "team.members.remove"):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only a team admin can remove members")
            removed = await run_in_threadpool(team_roles.remove_members, engine, team_id, principal, data.email_ids, meta)
            audit.mark_written(request)
            return {"message": "Members removed from the team", "removed": removed}
        elif data.intent == "add":
            role = data.role or DEFAULT_INVITE_ROLE
            if role not in invitable_roles(principal.role):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                    detail=f"Your role ({principal.role}) cannot give the {role} role"
                                           + (" by invitation: invite them, then make them an owner" if role == "owner" else ""))
            invited = await add_emails_to_team(data.email_ids, team_id, engine, invited_by_user_id=user.id, role=role)
            if await run_in_threadpool(_record_invites, engine, team_id, principal, meta, invited, role):
                audit.mark_written(request)  # else the middleware's generic event stands in
            return {"message": f"Invitation sent to {', '.join(invited)}", "invited": invited, "role": role}

        return {
            "message": "Members removed from the team",
        }
                
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in removing or adding members to team: {e}", style="red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error in removing or adding members to team: {e}")


# new ✅
@router.delete("/team/{team_id}",summary="Delete a team (owners)", dependencies=[Depends(write_limiter), access.team("team.delete")])
async def delete_team(
    team_id: int,
    request: Request,
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
            meta = request_meta(request)
            audit.record(session, action="team.delete", team_id=team_id, object_type="team", object_id=team_id,
                         ip=meta["ip"], user_agent=meta["user_agent"],
                         details={"name": (team.name or "")[:100], "scans_deleted": len(scan_ids_list)},
                         **audit.actor_fields(_principal(request)))
            session.delete(team)
            session.commit()
            audit.mark_written(request)
        console.print(f"Team with id: {team_id} deleted from main database" ,style="bold orange3")
        

        

    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in deleting team: {e}", style="red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error in deleting team: {e}")


# new ✅
@router.get("/team/{team_id}/dashboard",summary="Get the dashboard data for a team", dependencies=[Depends(read_limiter), access.team("team.read")])
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


@router.get("/teams/dashboard",summary="Get the dashboard data for all teams that the current user is a member of", dependencies=[Depends(read_limiter), access.authenticated()])
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

@router.get("/team/{team_id}/invitations", summary="Open invitations of the team (admin)",
            dependencies=[Depends(read_limiter), access.team("team.members.invite")])
async def list_team_invitations(team_id: int, Authorization: Annotated[str | None, Header()] = None):
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_admin_of_team(user.id, team_id, engine)
    return {"invitations": invitations.list_invitations(team_id, engine)}


@router.post("/team/{team_id}/invitations/{invitation_id}/resend",
             summary="Mail a new invitation link; the previous link stops working (admin)",
             dependencies=[Depends(write_limiter), access.team("team.members.invite")])
async def resend_team_invitation(team_id: int, invitation_id: int, request: Request,
                                 Authorization: Annotated[str | None, Header()] = None):
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_admin_of_team(user.id, team_id, engine)
    principal = _principal(request)
    sent = await invitations.resend_invitation(team_id, invitation_id, user.id, engine,
                                               may_give=invitable_roles(principal.role))
    if await run_in_threadpool(_record_invites, engine, team_id, principal, request_meta(request), [sent["email"]],
                               sent["role"], "team.members.invite.resend"):
        audit.mark_written(request)
    return {"message": "A new invitation link was sent"}


@router.delete("/team/{team_id}/invitations/{invitation_id}", summary="Revoke an invitation (admin)",
               dependencies=[Depends(write_limiter), access.team("team.members.invite")])
async def revoke_team_invitation(team_id: int, invitation_id: int, request: Request,
                                 Authorization: Annotated[str | None, Header()] = None):
    engine = get_db()
    user = await get_user_from_header_or_raise_exception(engine, Authorization)
    check_if_user_is_admin_of_team(user.id, team_id, engine)
    revoked = invitations.revoke_invitation(team_id, invitation_id, engine)
    if await run_in_threadpool(_record_invites, engine, team_id, _principal(request), request_meta(request),
                               [revoked["email"]], revoked["role"], "team.members.invite.revoke"):
        audit.mark_written(request)
    return {"message": "Invitation revoked"}


# ------------------------------------------------------------------------------------- roles (F4 RBAC)

@router.patch("/team/{team_id}/members/role", summary="Change a member's role (admins: member and viewer; owners: any)",
              dependencies=[Depends(write_limiter), access.team("team.members.role")])
async def change_member_role(team_id: int, data: ChangeMemberRoleData, request: Request):
    """Admins move members and viewers between those two roles; owners give and take any role, including owner.
    Nobody but an owner changes their own role, and a team always keeps one owner (409).  The change applies to
    the member's next request: roles are read from the database, never from the token."""
    result = await run_in_threadpool(team_roles.change_role, get_db(), team_id, _principal(request), data.email,
                                     data.role, request_meta(request))
    audit.mark_written(request)
    return result


@router.post("/team/{team_id}/ownership/claim", summary="Become the owner of a team that has none (admins)",
             dependencies=[Depends(write_limiter), access.team("team.ownership.claim")])
async def claim_team_ownership(team_id: int, request: Request):
    """An ownerless team's only admin becomes its owner.  Refused (409) once the team has an owner, and when it has
    several admins (a platform operator chooses: POST /admin/teams/{id}/owner)."""
    result = await run_in_threadpool(team_roles.claim_ownership, get_db(), team_id, _principal(request),
                                     request_meta(request))
    audit.mark_written(request)
    return result


@router.get("/team/{team_id}/audit", summary="The team's audit log, newest first (admins)",
            dependencies=[Depends(read_limiter), access.team("team.audit.read")])
async def team_audit_log(team_id: int,
                         limit: Annotated[int, Query(ge=1, le=200)] = 50,
                         before_id: Annotated[int | None, Query(ge=1)] = None,
                         action: Annotated[str | None, Query(max_length=64)] = None,
                         actor_email: Annotated[str | None, Query(max_length=254)] = None,
                         outcome: Annotated[str | None, Query(pattern="^(success|denied)$")] = None):
    return await run_in_threadpool(audit.list_events, get_db(), team_id=team_id, limit=limit, before_id=before_id,
                                   action=action, actor_email=actor_email, outcome=outcome)


@router.get("/rbac/matrix", summary="Roles and what each may do", dependencies=[Depends(read_limiter), access.authenticated()])
async def rbac_matrix():
    return matrix()
