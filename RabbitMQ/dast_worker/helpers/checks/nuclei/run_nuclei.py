import subprocess
import tempfile
from helpers.general.dir_load import load_dir_to_documents
import shutil
from rich.console import Console
console = Console()

def run_nuclei(url: str, template_path: str):
    
    try: 
        # STEP [ 1 ] -------------- create temp output report file --------------
        temp_dir = tempfile.mkdtemp(prefix="nuclei_")


        # STEP [ 2 ] -------------- run nuclei --------------
        command = [
            "nuclei",
            "-u", url,
            "-headless",
            "-t", template_path,
            "-me", temp_dir,
        ]
        console.print(f"Running nuclei with command: {command}", style="bold green")
        subprocess.run(command, check=True)

        # STEP [ 3 ] ----------- Load Documents from the temp directory --------------
        documents = load_dir_to_documents(temp_dir)
        console.print(f"Loaded {len(documents)} documents from the temp directory", style="bold green")

        # STEP [ 4 ] ----------- Return the documents --------------
        return documents

    except Exception as e:
        console.print(f"Error in nuclei: {str(e)}", style="bold red")
        raise e 
    
    finally:
        # STEP [ 5 ] ----------- Delete the temp directory --------------
        shutil.rmtree(temp_dir)
        console.print(f"Deleted the temp directory", style="bold green")