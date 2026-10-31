from io import BytesIO
import tempfile
import boto3
from botocore.exceptions import ClientError
import os
import uuid
from datetime import datetime
from dotenv import load_dotenv
from rich.console import Console
from pathlib import Path

load_dotenv()
console = Console()

def show_upload_progress(no_of_bytes_uploaded : int ):
    console.print(f"Uploaded {no_of_bytes_uploaded} bytes of the file ",style="bold blue1")

def show_download_progress(no_of_bytes_downloaded : int ):
    console.print(f"Downloaded {no_of_bytes_downloaded} bytes of the file ",style="bold orange3")

def _s3_client():
    aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    region_name = os.getenv("AWS_DEFAULT_REGION")
    if not aws_access_key_id or not aws_secret_access_key or not region_name:
        raise Exception("AWS credentials are not set")
    kwargs = {
        "aws_access_key_id": aws_access_key_id,
        "aws_secret_access_key": aws_secret_access_key,
        "region_name": region_name,
    }
    endpoint = os.getenv("AWS_ENDPOINT_URL_S3")
    if endpoint:
        kwargs["endpoint_url"] = endpoint
    return boto3.client("s3", **kwargs)

def upload_zip_file(file_handle : any , bucket):
    try:
        # STEP [ 1 ] : =========================== create a s3 client ========================================
        console.print(f"Creating a s3 client",style="bold yellow")
        s3_client = _s3_client()


        # STEP [ 2 ] : ============================= create name for the file in the s3 bucket ========================================
        console.print(f"Creating a name for the file in the s3 bucket",style="bold yellow")
        object_name = "file-" + str(datetime.now().strftime("%Y%m%d%H%M%S%f")) + "-" + str(uuid.uuid4())[:8] + ".zip"
    
    
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

def download_zip_file(bucket : str, object_name : str):
    try:
        # STEP [ 1 ] : =========================== create a s3 client ========================================
        console.print(f"Creating a s3 client",style="bold yellow")
        s3_client = _s3_client()

        # STEP [ 2 ] : =========================== download the file from the s3 bucket to temp file ========================================
        console.print(f"Downloading the zip file from the s3 bucket to temp file",style="bold yellow")
        temp_zip_file = tempfile.NamedTemporaryFile(delete=False, suffix=".zip" , mode="w+")
        temp_zip_file.close()
        response = s3_client.download_file(Bucket=bucket, Key=object_name, Filename=temp_zip_file.name, Callback=show_download_progress)
        return temp_zip_file.name

    except Exception as e:
        console.print(f"Error downloading zip file: {e}",style="bold red")
        return None


def download_file(bucket : str, object_name : str):
    try:
        # STEP [ 1 ] : =========================== create a s3 client ========================================
        console.print(f"Creating a s3 client",style="bold yellow")
        s3_client = _s3_client()

        # STEP [ 2 ] : =========================== download the file from the s3 bucket to temp file ========================================
        file_extension = object_name.split(".")[-1]
        
        console.print(f"Downloading the file from the s3 bucket to temp file",style="bold yellow")
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f".{file_extension}" , mode="w+")
        temp_file.close()
        response = s3_client.download_file(Bucket=bucket, Key=object_name, Filename=temp_file.name, Callback=show_download_progress)
        return temp_file.name
    
    except Exception as e:
        console.print(f"Error downloading file: {e}",style="bold red")
        return None

def delete_file(bucket : str, object_name : str):
    try:
        # STEP [ 1 ] : =========================== create a s3 client ========================================
        console.print(f"Creating a s3 client",style="bold yellow")
        s3_client = _s3_client()
        
        # STEP [ 2 ] : =========================== delete the file from the s3 bucket ========================================
        console.print(f"Deleting the file from the s3 bucket",style="bold yellow")
        s3_client.delete_object(Bucket=bucket, Key=object_name)

        # An empty bucket omits Contents. head_object is the delete check.
        try:
            s3_client.head_object(Bucket=bucket, Key=object_name)
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            http_status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if code in {"404", "NoSuchKey", "NotFound"} or http_status == 404:
                return True
            raise
        return False
    except Exception as e:
        console.print(f"Error deleting file: {e}",style="bold red")
        return False

if __name__ == "__main__":
    zip_file_path = "C:\\Users\\HP\\Downloads\\RiskPilot-main.zip"
    with open(zip_file_path, "rb") as f:
        bytes_io_object = BytesIO(f.read())
    
    response = upload_zip_file(bytes_io_object, "devsecshield-storage")
    print(response)
    # download_path = download_file("devsecshield-storage", response["object_name"])
    # print(download_path)