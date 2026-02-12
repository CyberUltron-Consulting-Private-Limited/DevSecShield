from celery import Task


class StateUpdateWriter:
    
    def __init__(self, task : Task):
        self.task : Task = task
    

    def write_progress_percentage(self, progress : float):
        self.task.update_state(state="STARTED", meta={"current": progress})
    

    def write_progress_out_of_total(self, current : int, total : int):
        self.task.update_state(state="STARTED", meta={"current": current, "total": total})
    
    
    def update_state_with_meta(self, meta : dict):
        self.task.update_state(state="STARTED", meta=meta)
    
    
    