from celery import Celery
from celery.result import AsyncResult
from fastapi import HTTPException, status
from pymongo.collection import Collection
from bson import ObjectId
import time
from rich.console import Console

console = Console()

def poll_for_results(
    task_id: str, 
    celery_app: Celery , 
    cicd_log_collection: Collection,
    CICD_LOG_ID: str
) -> dict:
    """
    Poll for the results of a task
    """
    for i in range(20):
        time.sleep(10)
        task_status = AsyncResult(task_id, app=celery_app).status.lower() if task_id else None
        if not task_status:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get status of task")
        if task_status == "success":
            results = AsyncResult(task_id, app=celery_app).result if (task_id and AsyncResult(task_id, app=celery_app).result )else None
            if not results:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to get results of task")
            cicd_log_collection.update_one({"_id": ObjectId(CICD_LOG_ID)}, {"$set": {"results": results, "status": task_status}})
            console.print(f"Cicd log updated successfully with id: {CICD_LOG_ID} and results", style="bold green")
            return results
        if task_status == "failure":
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to run ci cd scan")

        cicd_log_collection.update_one({"_id": ObjectId(CICD_LOG_ID)}, {"$set": {"status": task_status}})
        console.print(f"Cicd log updated successfully with id: {CICD_LOG_ID} and status: {task_status}", style="bold green")