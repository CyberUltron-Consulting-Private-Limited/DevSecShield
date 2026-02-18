import subprocess
import tempfile
from rich.console import Console
console = Console()

def run_nuclei(url: str, template_path: str):
    
    try: 
        # STEP [ 1 ] -------------- create temp output report file --------------
        pass


    except Exception as e:
        console.print(f"Error in nuclei: {str(e)}", style="bold red")
        raise e 