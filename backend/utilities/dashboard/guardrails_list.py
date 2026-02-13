from backend.get_db import get_db , get_mongo_client_db
from sqlmodel import Session, select
from backend.new_models import GuardrailsIntegration , Team 
from fastapi import HTTPException
import pymongo
from rich.console import Console
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from backend.get_db import dev_environment
console = Console()

def create_dashboard_data_for_guardrails_list(team_id: int):
    try:
        engine = get_db(dev_environment=dev_environment)
        mongo_db = get_mongo_client_db(dev_environment=dev_environment)
        guardrails_logs_collection = mongo_db["guardrails_logs"]

        integration_ids = []
        with Session(engine) as session:
            integrations = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.team_id == team_id)).all()
            if not integrations:
                raise HTTPException(status_code=404, detail="No integrations found for this team")
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
        
        total_logs , pending_logs , started_logs , not_started_logs , success_logs , failure_logs = len(log_data), 0, 0, 0, 0, 0
        past_30_days_risk_score_data = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        high_or_critical_risks_daily_usage = defaultdict(int)
        for log in log_data:
            
            created_at : datetime = log["created_at"]
            created_at = created_at.replace(tzinfo=timezone.utc)



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

            if log["results"] is None:
                continue
            
            # ------------------> categorizing risk scores in the past 30 days 
            if created_at > datetime.now(timezone.utc) - timedelta(days=30):
                for key , value in log["results"].items():
                    if key in [ "Anonymize" , "Toxicity" , "TokenLimit" , "PromptInjection" , "Regex" , "Code" , "Secrets" ]:
                        if value["score"] > 0.9: 
                            past_30_days_risk_score_data["critical"] += 1
                        elif value["score"] > 0.7 and value["score"] <= 0.9:
                            past_30_days_risk_score_data["high"] += 1
                        elif value["score"] > 0.5 and value["score"] <= 0.7:
                            past_30_days_risk_score_data["medium"] += 1
                        elif value["score"] > 0.3 and value["score"] <= 0.5:
                            past_30_days_risk_score_data["low"] += 1
                        elif value["score"] > 0.1 and value["score"] <= 0.3:
                            past_30_days_risk_score_data["low"] += 1
            """
            past 30 days risk score data will look like this : 
            {
                "critical": 10,
                "high": 20,
                "medium": 30,
                "low": 40,
            }
            """
            
            # -------------------> categorizing high or critical risks in the past 30 days 
            if created_at > datetime.now(timezone.utc) - timedelta(days=30):
                for key , value in log["results"].items():
                    if key in [ "Anonymize" , "Toxicity" , "Tokenlimit" , "Promptinjection" , "Regex" , "Code" , "Secrets" ]:
                        if value["score"] > 0.9: 
                            high_or_critical_risks_daily_usage[created_at.date()] += 1
                        elif value["score"] > 0.7 and value["score"] <= 0.9:
                            high_or_critical_risks_daily_usage[created_at.date()] += 1
            """
            high or critical risks daily usage will look like this : 
            {
                "2026-01-01": 10,
                "2026-01-02": 20,
                "2026-01-03": 30,
            }
            """


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

            