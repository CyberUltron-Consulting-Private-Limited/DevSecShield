from collections import defaultdict
from backend.get_db import get_db, get_mongo_client_db
from fastapi import HTTPException
from rich.console import Console
from datetime import datetime, timedelta, timezone
from typing import TypedDict
from backend.new_models import GuardrailsIntegration
from sqlmodel import select , Session

console = Console()

class CardData(TypedDict):
    total_logs: int
    total_logs_today: int
    percentage_increase_or_decrease_in_total_logs_compared_to_yesterday: float
    total_logs_this_month: int
    total_active_scanners: int

class Past30DaysRiskScoreData(TypedDict):
    critical: int
    high: int
    medium: int
    low: int

class Past60DaysRiskScoreData(TypedDict):
    critical: int
    high: int
    medium: int
    low: int


class RadialChartData(TypedDict):
    total_logs: int
    successful_logs: int
    failed_logs: int
    pending_logs: int
    started_logs: int
    not_started_logs: int


class DashboardData(TypedDict):
    card_data: CardData
    radial_chart_data: RadialChartData
    recent_daily_detections_usage: dict[str, int]
    high_or_critical_risks_daily_usage: dict[str, int]
    past_30_days_risk_score_data: Past30DaysRiskScoreData
    past_60_days_risk_score_data: Past60DaysRiskScoreData

def get_guardrails_integration_dashboard_data(team_id: int, integration_id: int):
    """
    Get the integration dashboard data.
    """
    try:
        # STEP [ 1 ] : ======================================== Get database ====================================
        engine = get_db()
        mongo_db = get_mongo_client_db()
        guardrails_logs_collection = mongo_db["guardrails_logs"]

        # STEP [ 2 ] : ============================= Fetch all guardrail logs for integration ====================================
       
        card_data : CardData = {
            "total_logs": 0,
            "total_logs_today": 0,
            "percentage_increase_or_decrease_in_total_logs_compared_to_yesterday": 0,
            "total_logs_this_month": 0,
            "total_active_scanners": 0
        }
        radial_chart_data : dict[str, int] = {
            "total_logs": 0,
            "successful_logs": 0,
            "failed_logs": 0,
            "pending_logs": 0,
            "started_logs": 0,
            "not_started_logs": 0
        }

        recent_daily_detections_usage : dict[str, int] = defaultdict(int)
        past_30_days_risk_score_data : Past30DaysRiskScoreData = {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0
                    }
        past_60_days_risk_score_data : Past60DaysRiskScoreData = {
                        "critical": 0,
                        "high": 0,
                        "medium": 0,
                        "low": 0
                    }
        high_or_critical_risks_daily_usage : dict[str, int] = defaultdict(int)


        total_logs_yesterday : int = 0
        total_scanners : int = 0
        with Session(engine) as session:
            integration = session.exec(select(GuardrailsIntegration).where(GuardrailsIntegration.id == integration_id)).first()
            if integration is None:
                raise HTTPException(status_code=404, detail="Integration not found")
            
            #calculating total numbers of scanners in the integration
            for key, value in integration.settings.items():
                if key in [ "Anonymize" , "Toxicity" , "TokenLimit" , "PromptInjection" , "Regex" , "Code" , "Secrets" ] and value:
                    total_scanners += 1
        
        card_data["total_active_scanners"] = total_scanners
                    

        with guardrails_logs_collection.find({"integration_id": integration_id}).sort("created_at", -1) as cursor:
            for log in cursor:
                created_at : datetime = log["created_at"]
                created_at = created_at.replace(tzinfo=timezone.utc)


                # -----------------> populating card data 
                card_data["total_logs"] += 1
                
                
                # calculating the total logs for today and yesterday 
                today_date = datetime.now(timezone.utc).date()
                yesterday_date = today_date - timedelta(days=1)
                if created_at.date() == today_date:
                    card_data["total_logs_today"] += 1
                elif created_at.date() == yesterday_date:
                    total_logs_yesterday += 1 # will later be used to calculate the % increase or decrease in total logs compared to yesterday
                
                # total logs this month 
                if created_at.month == datetime.now(timezone.utc).month:
                    card_data["total_logs_this_month"] += 1
                
                    

                # -------------------> recent ( past 30 days ) daily detections / usage 
                if created_at > datetime.now(timezone.utc) - timedelta(days=30):
                    recent_daily_detections_usage[created_at.date()] += 1 
                
                radial_chart_data["total_logs"] += 1
                if log["status"] == "success":
                    radial_chart_data["successful_logs"] += 1
                elif log["status"] == "failure":
                    radial_chart_data["failed_logs"] += 1
                elif log["status"] == "pending":
                    radial_chart_data["pending_logs"] += 1
                elif log["status"] == "started":
                    radial_chart_data["started_logs"] += 1
                elif log["status"] == "NOT_STARTED":
                    radial_chart_data["not_started_logs"] += 1
                
                if log["results"] is None:
                        continue
                
                


                try : 
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
                    
                    # ------------------> categorizing risk scores in the past 60 days 
                    if created_at > datetime.now(timezone.utc) - timedelta(days=60):
                        for key , value in log["results"].items():
                            if key in [ "Anonymize" , "Toxicity" , "TokenLimit" , "PromptInjection" , "Regex" , "Code" , "Secrets" ]:
                                if value["score"] > 0.9: 
                                    past_60_days_risk_score_data["critical"] += 1
                                elif value["score"] > 0.7 and value["score"] <= 0.9:
                                    past_60_days_risk_score_data["high"] += 1
                                elif value["score"] > 0.5 and value["score"] <= 0.7:
                                    past_60_days_risk_score_data["medium"] += 1
                                elif value["score"] > 0.3 and value["score"] <= 0.5:
                                    past_60_days_risk_score_data["low"] += 1
                                elif value["score"] > 0.1 and value["score"] <= 0.3:
                                    past_60_days_risk_score_data["low"] += 1
                    

                    
                    

                    # -------------------> categorizing high or critical risks in the past 30 days 
                    if created_at > datetime.now(timezone.utc) - timedelta(days=30):
                        for key , value in log["results"].items():
                            if key in [ "Anonymize" , "Toxicity" , "TokenLimit" , "PromptInjection" , "Regex" , "Code" , "Secrets" ]:
                                if value["score"] > 0.9: 
                                    high_or_critical_risks_daily_usage[created_at.date()] += 1
                                elif value["score"] > 0.7 and value["score"] <= 0.9:
                                    high_or_critical_risks_daily_usage[created_at.date()] += 1

                  
                except Exception as e:
                    console.print(f"Error categorizing risk scores: {str(e)}", style="bold red")
                    continue
            

            
            
            if total_logs_yesterday > 0:
                card_data["percentage_increase_or_decrease_in_total_logs_compared_to_yesterday"] = (card_data["total_logs_today"] - total_logs_yesterday) / total_logs_yesterday * 100
            else:
                card_data["percentage_increase_or_decrease_in_total_logs_compared_to_yesterday"] = 0.0
            
            data =  {
                "card_data": card_data,
                "radial_chart_data": radial_chart_data,
                "recent_daily_detections_usage": recent_daily_detections_usage,
                "past_30_days_risk_score_data": past_30_days_risk_score_data,
                "past_60_days_risk_score_data": past_60_days_risk_score_data,
                "high_or_critical_risks_daily_usage": high_or_critical_risks_daily_usage,
            }


            return data

            # return {
            #     "card_data": { 
            #         "total_logs": 12,
            #         "successful_logs": 1,
            #         "failed_logs": 2,
            #         "pending_logs": 3,
            #         "started_logs": 4,
            #         "not_started_logs": 1
            #     },
            #     "recent_daily_detections_usage": {
            #         "2026-01-01": 1,
            #         "2026-01-02": 1,
            #         "2026-01-03": 13,
            #         "2026-01-04": 14,
            #         "2026-01-05": 11,
            #         "2026-01-06": 1,
            #         "2026-01-07": 111,
            #         "2026-01-08": 19,
            #         "2026-01-09": 20,
            #         "2026-01-10": 1
            #     },
            #     "past_30_days_risk_score_data": {
            #         "critical": 1,
            #         "high": 7,
            #         "medium": 4,
            #         "low": 1
            #     },
            #     "past_60_days_risk_score_data": {
            #         "critical": 1,
            #         "high": 7,
            #         "medium": 1,
            #         "low": 4
            #     },
            #     "high_or_critical_risks_daily_usage": {
            #         "2026-01-01": 1,
            #         "2026-01-02": 1,
            #         "2026-01-03": 13,
            #         "2026-01-04": 14,
            #         "2026-01-05": 11,
            #         "2026-01-06": 1,
            #         "2026-01-07": 111,
            #         "2026-01-08": 19,
            #         "2026-01-09": 20,
            #         "2026-01-10": 1,
            #         "2026-01-11": 1,
            #         "2026-01-12": 1,
            #         "2026-01-13": 1,
            #         "2026-01-14": 1,
            #         "2026-01-15": 1,
            #         "2026-01-16": 1,
            #         "2026-01-17": 1,
            #         "2026-01-18": 1,
            #     }
            # }


                
    except Exception as e:
        console.print(f"Error getting guardrails integration dashboard data: {str(e)}", style="bold red")
        raise HTTPException(status_code=500, detail="Error getting guardrails integration dashboard data")