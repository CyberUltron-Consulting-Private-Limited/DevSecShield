from io import BytesIO
import tempfile
import boto3
from botocore.exceptions import ClientError
import os
import uuid
from datetime import datetime
from dotenv import load_dotenv
from rich.console import Console

load_dotenv()
console = Console()

def show_upload_progress(no_of_bytes_uploaded : int ):
    console.print(f"Uploaded {no_of_bytes_uploaded} bytes of the file ",style="bold blue1")

def show_download_progress(no_of_bytes_downloaded : int ):
    console.print(f"Downloaded {no_of_bytes_downloaded} bytes of the file ",style="bold orange3")

def upload_file(
    file_handle : any , 
    bucket : str = "devsecshield-storage", 
    extension : str = ".zip",
    file_name : str = None,
    ):
    """
    Returns 
    {
        "bucket": bucket,
        "object_name": object_name
    }
    """
    try:
        # STEP [ 1 ] : =========================== create a s3 client ========================================
        console.print(f"Creating a s3 client",style="bold yellow")
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
        region_name=os.getenv("AWS_DEFAULT_REGION")
        if not aws_access_key_id or not aws_secret_access_key or not region_name:
            raise Exception("AWS credentials are not set")

        s3_client = boto3.client('s3',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name
        )


        # STEP [ 2 ] : ============================= create name for the file in the s3 bucket ========================================
        console.print(f"Creating a name for the file in the s3 bucket",style="bold yellow")
        if file_name:
            object_name = file_name 
        else:
            object_name = "file-" + str(datetime.now().strftime("%Y%m%d%H%M%S%f")) + "-" + str(uuid.uuid4())[:8] + extension
    
    
        # STEP [ 3 ] : =========================== upload the file to the s3 bucket ========================================
        console.print(f"Uploading the file to the s3 bucket",style="bold yellow")
        response = s3_client.upload_fileobj(Fileobj=file_handle, Bucket=bucket, Key=object_name , ExtraArgs=None, Callback=show_upload_progress, Config=None)
        
        return {
            "bucket": bucket,
            "object_name": object_name
        }
    except Exception as e:
        console.print(f"Error uploading file: {e}",style="bold red")
        return None

def download_file(bucket : str, object_name : str):
    try:
        # STEP [ 1 ] : =========================== create a s3 client ========================================
        console.print(f"Creating a s3 client",style="bold yellow")
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
        region_name=os.getenv("AWS_DEFAULT_REGION")
        if not aws_access_key_id or not aws_secret_access_key or not region_name:
            raise Exception("AWS credentials are not set")

        s3_client = boto3.client('s3',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name
        )

        # STEP [ 2 ] : =========================== download the file from the s3 bucket to temp file ========================================
        console.print(f"Downloading the file from the s3 bucket to temp file",style="bold yellow")
        temp_zip_file = tempfile.NamedTemporaryFile(delete=False, suffix=".zip" , mode="w+")
        temp_zip_file.close()
        response = s3_client.download_file(Bucket=bucket, Key=object_name, Filename=temp_zip_file.name, Callback=show_download_progress)
        return temp_zip_file.name

    except Exception as e:
        console.print(f"Error downloading file: {e}",style="bold red")
        return None


def delete_file(bucket : str, object_name : str):
    try:
        # STEP [ 1 ] : =========================== create a s3 client ========================================
        console.print(f"Creating a s3 client",style="bold yellow")
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
        region_name=os.getenv("AWS_DEFAULT_REGION")
        if not aws_access_key_id or not aws_secret_access_key or not region_name:
            raise Exception("AWS credentials are not set")
        
        s3_client = boto3.client('s3',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region_name
        )
        
        # STEP [ 2 ] : =========================== delete the file from the s3 bucket ========================================
        console.print(f"Deleting the file from the s3 bucket",style="bold yellow")
        response = s3_client.delete_object(Bucket=bucket, Key=object_name)

        # STEP [ 3 ] : ======================= check if the file is deleted  and return true if it is deleted ========================================
        
        # listing out all the objects in the bucket
        objects = s3_client.list_objects(Bucket=bucket)
        if not objects["Contents"]:
            return True
        for obj in objects["Contents"]:
            # console.print(f"Object: {obj['Key']} found in the bucket",style="bold yellow")
            if obj["Key"] == object_name:
                return False
        else:
            return True
    except Exception as e:
        console.print(f"Error deleting file: {e}",style="bold red")
        return False


if __name__ == "__main__":
    # zip_file_path = "C:\\Users\\HP\\Downloads\\gitleaks_8.28.0_windows_x64.zip"
    # with open(zip_file_path, "rb") as f:
    #     bytes_io_object = BytesIO(f.read())
    
    # response = upload_file(bytes_io_object, "devsecshield-storage")
    # print(response)
    # download_path = download_file("devsecshield-storage", response["object_name"])
    # print(download_path)
    response = delete_file("devsecshield-storage", "2nd_scan_report.pdf")
    print(response)