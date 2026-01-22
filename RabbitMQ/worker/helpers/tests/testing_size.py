import os
from rich.console import Console
console = Console()

def get_size(start_path = '.'):
    total_size = 0
    total_files = 0
    console.print(f"Starting to calculate size of {start_path}",style="bold yellow")
    for dirpath, dirnames, filenames in os.walk(start_path):
        for f in filenames:
            extension = f.split(".")[-1]
            fp = os.path.join(dirpath, f)
            # skip if it is symbolic link
            if not os.path.islink(fp) and extension == "py" and ".venv" not in fp:
                total_size += os.path.getsize(fp)
                total_files += 1
                console.print(f"Processing file: {f}",style="dim yellow")
    
    #converting to MB 
    total_size_mb = total_size / 1024 / 1024

    #converting to GB
    total_size_gb = total_size_mb / 1024

    console.print(f"Total size: {total_size_gb} GB ( {total_size_mb} MB ) ( {total_size} bytes ) ( {total_files} files )",style="bold yellow")

get_size("C:\\Users\\HP\\AppData\\Local\\Temp\\repo_n4hky4d2")
# get_size("C:\\Users\\HP\\Downloads\\transformers-main")