"""DEPRECATED: Guardrails list-page dashboard aggregation.

Retained for legacy Guardrails router responses. Not surfaced in the product UI.
"""

from backend.get_db import get_db , get_mongo_client_db
from sqlmodel import Session, select
from backend.new_models import GuardrailsIntegration , Team 
from fastapi import HTTPException
import pymongo
from rich.console import Console
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Optional
console = Console()

def create_dashboard_data_for_guardrails_list(team_id: int):
    try:
        engine = get_db()
        mongo_db = get_mongo_client_db()
        guardrails_logs_collection = mongo_db["guardrails_logs"]

        integration_ids = []
        with Session(engine) as session:
            integrations = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.team_id == team_id)).all()
            if not integrations:
                return None
            for integration in integrations:
                # console.print(f"Integration : {integration.title} {integration.id} , team id : {integration.team_id}", style="bold yellow")
                integration_ids.append(integration.id)
        
        

        log_data = []
        for integration_id in integration_ids:
            with guardrails_logs_collection.find({"integration_id": integration_id}).sort("created_at", pymongo.DESCENDING) as cursor:
                for log in cursor:
                    # console.print(f"Integration ID : {integration_id} Log : {log}", style="bold yellow")
                    log_data.append({
                        "id": str(log["_id"]),
                        "status": log["status"],
                        "created_at": log["created_at"],
                        "input_prompt": log["input_prompt"],
                        "results": log["results"],
                    })
        
        total_logs, pending_logs, started_logs, not_started_logs, success_logs, failure_logs = len(log_data), 0, 0, 0, 0, 0
        past_30_days_risk_score_data = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        high_or_critical_risks_daily_usage = defaultdict(int)

        now_utc = datetime.now(timezone.utc)
        cutoff_30_days = now_utc - timedelta(days=30)
        cutoff_14_days = now_utc - timedelta(days=14)

        for log in log_data:
            created_at: datetime = log["created_at"]
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            else:
                created_at = created_at.astimezone(timezone.utc)

            if log["status"].lower() == "pending":
                pending_logs += 1
            elif log["status"].lower() == "started":
                started_logs += 1
            elif log["status"].lower() == "not_started":
                not_started_logs += 1
            elif log["status"].lower() == "success":
                success_logs += 1
            elif log["status"].lower() == "failure":
                failure_logs += 1

            results = log.get("results")
            if not results or not isinstance(results, dict):
                continue

            def _valid_score(val: object) -> Optional[float]:
                """Return numeric score in [0, 1] or None if invalid. Score -1 is invalid (treat as 0 / skip)."""
                if not isinstance(val, dict):
                    return None
                s = val.get("score")
                if s is None or not isinstance(s, (int, float)) or s < 0 or s > 1:
                    return None
                return float(s)

            # Past 30 days: count each guardrail result by severity (skip invalid scores like -1)
            if created_at > cutoff_30_days:
                for key, value in results.items():
                    score = _valid_score(value)
                    if score is None:
                        continue
                    if score > 0.9:
                        past_30_days_risk_score_data["critical"] += 1
                    elif score > 0.7:
                        past_30_days_risk_score_data["high"] += 1
                    elif score > 0.5:
                        past_30_days_risk_score_data["medium"] += 1
                    elif score > 0.1:
                        past_30_days_risk_score_data["low"] += 1

            # Past 14 days: count high or critical risks per day (score > 0.7, valid only)
            if created_at > cutoff_14_days:
                for key, value in results.items():
                    score = _valid_score(value)
                    if score is None or score <= 0.7:
                        continue
                    high_or_critical_risks_daily_usage[created_at.date()] += 1


        card_data = {
            "total_logs": total_logs,
            "pending_logs": pending_logs,
            "started_logs": started_logs,
            "not_started_logs": not_started_logs,
            "success_logs": success_logs,
            "failure_logs": failure_logs,
        }

        return {
            "card_data": card_data,
            "past_30_days_risk_score_data": past_30_days_risk_score_data,
            "high_or_critical_risks_daily_usage": high_or_critical_risks_daily_usage,
        }
        
    
    except HTTPException as e:
        console.print(f"Error in creating dashboard data for guardrails list: {e}", style="dim red")
        raise e
    except Exception as e:
        console.print(f"Error in creating dashboard data for guardrails list: {e}", style="dim red")
        raise HTTPException(status_code=500, detail="Internal server error")

            