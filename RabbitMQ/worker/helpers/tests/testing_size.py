import os
from rich.console import Console
from helpers.context.measure_size import get_size_of_documents
from helpers.context.codebase_context import CodebaseContext
from helpers.context.scan_context import ZipContext, get_directory_from_zip_context
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

# get_size("C:\\Users\\HP\\AppData\\Local\\Temp\\repo_n4hky4d2")
# get_size("C:\\Users\\HP\\Downloads\\transformers-main")
# get_size("C:\\Users\\HP\\Desktop\\DevSecShield")
# get_size("C:\\Users\\HP\\Desktop\\RiskPilot")


if __name__ == "__main__":


    included_path_arrays = [[".tf"]]
    excluded_path_arrays = [ ["api_routes"],["normal_scan_utils"],["mcpscan_utils"],["llm_scan_utils"]]

    zip_context = ZipContext(
            bucket_name="devsecshield-storage",
            object_name="RiskPilot-main (1).zip" # size : Total size: 0.0002691037952899933 GB ( 0.2755622863769531 MB ) ( 288948 bytes ) ( 36 files ) , cost : 0.08 $ ( ~ 7 INR )
            # object_name="DevSecShield-main.zip" # size : Total size: 0.000959618017077446 GB ( 0.9826488494873047 MB ) ( 1030382 bytes ) ( 153 files ) , cost : 0.182 $ ( ~ 16.7 INR )
        )
    directory = get_directory_from_zip_context(zip_context)

    
    #testing codebase context
    # directory = Path("C:/Users/HP/Desktop/RiskPilot - Copy/backend")
    codebase_context = CodebaseContext(
        directory=directory, 
        include_files_extensions=[".py"],
        exclude_path_arrays=[[".venv"],["__pycache__"],["venv"]],
        # include_path_arrays=included_path_arrays,
    )

    codebase_context.split_documents_and_set_documents()

    documents = codebase_context.documents
    size = get_size_of_documents(documents)
    console.print(f"Size of documents: {size} bytes",style="bold yellow")


    # get_size("C:\\Users\\HP\\Downloads\\DevSecShield-main")

