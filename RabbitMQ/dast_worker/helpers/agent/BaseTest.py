


class BaseTest():


    def __init__(self, url: str, template_path: str):
        raise NotImplementedError("Subclasses must implement this method")

    
    def run(self):
        raise NotImplementedError("Subclasses must implement this method")
    
    
    def get_summary(self):
        raise NotImplementedError("Subclasses must implement this method")
    
    
    
    