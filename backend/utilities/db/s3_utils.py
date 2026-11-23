from io import BytesIO
import logging
import os
import re
import tempfile

import boto3
from boto3.exceptions import S3UploadFailedError
from botocore.exceptions import ClientError
from fastapi import HTTPException, status
import uuid
from datetime import datetime
from dotenv import load_dotenv
from rich.console import Console

load_dotenv()
console = Console()
logger = logging.getLogger(__name__)

# Where uploads are stored. Configurable per deployment (staging may use another bucket, region or an S3-compatible
# endpoint such as MinIO); the defaults are the values this module always used.
DEFAULT_BUCKET = "devsecshield-storage"


def storage_bucket() -> str:
    """``S3_BUCKET``, else the historic bucket name."""
    return (os.getenv("S3_BUCKET") or "").strip() or DEFAULT_BUCKET


def storage_region() -> str | None:
    """``S3_REGION``, else ``AWS_DEFAULT_REGION``."""
    return (os.getenv("S3_REGION") or "").strip() or (os.getenv("AWS_DEFAULT_REGION") or "").strip() or None


def storage_endpoint() -> str | None:
    """``AWS_ENDPOINT_URL_S3`` (an S3-compatible endpoint), else AWS's own."""
    return (os.getenv("AWS_ENDPOINT_URL_S3") or "").strip() or None


# AWS error code -> the reason a user may see. Nothing here names a key, a bucket or an account.
_PUBLIC_REASON = {
    "InvalidAccessKeyId": "the storage credentials were rejected",
    "SignatureDoesNotMatch": "the storage credentials were rejected",
    "ExpiredToken": "the storage credentials have expired",
    "InvalidToken": "the storage credentials were rejected",
    "AccessDenied": "access to the storage bucket was denied",
    "AllAccessDisabled": "access to the storage bucket was denied",
    "NoSuchBucket": "the storage bucket does not exist",
    "PermanentRedirect": "the storage bucket is in another region",
    "AuthorizationHeaderMalformed": "the storage region is misconfigured",
    "NotConfigured": "file storage is not configured on this server",
    "EndpointConnectionError": "the storage service could not be reached",
    "ConnectTimeoutError": "the storage service could not be reached",
    "ReadTimeoutError": "the storage service did not answer in time",
    "NoCredentialsError": "file storage is not configured on this server",
    "SlowDown": "the storage service is throttling requests",
    "ServiceUnavailable": "the storage service is unavailable",
}


class StorageUnavailable(HTTPException):
    """An upload to file storage failed: 503 with a reason that names no secret.

    ``aws_code`` (the AWS error code, or the botocore exception class) and ``operation`` are for logs and tests;
    the ``detail`` the API returns says only what failed and that nothing was stored. Raised as an HTTPException so
    every route (UI scans, estimates, the CI/CD gate) answers 503 instead of a generic 500.
    """

    def __init__(self, aws_code: str, operation: str = "upload") -> None:
        self.aws_code = aws_code
        self.operation = operation
        reason = _PUBLIC_REASON.get(aws_code, "the storage service returned an error")
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"File storage is unavailable ({reason}); the file was not stored. "
                   f"Try again later or ask your administrator to check the storage settings. (code: {aws_code})",
            headers={"Retry-After": "60"},
        )


def _aws_code(exc: BaseException) -> str:
    """The AWS error code of a ClientError, else the botocore/boto3 exception class name."""
    if isinstance(exc, ClientError):
        code = str((exc.response or {}).get("Error", {}).get("Code") or "")
        if code:
            return code
    if isinstance(exc, S3UploadFailedError) and exc.__cause__ is not None:
        return _aws_code(exc.__cause__)
    if isinstance(exc, S3UploadFailedError):  # boto3 folds the ClientError into the message: "... (NoSuchBucket) ..."
        found = re.search(r"\(([A-Za-z]+)\)", str(exc))
        if found:
            return found.group(1)
    return type(exc).__name__


def show_upload_progress(no_of_bytes_uploaded : int ):
    console.print(f"Uploaded {no_of_bytes_uploaded} bytes of the file ",style="bold blue1")

def show_download_progress(no_of_bytes_downloaded : int ):
    console.print(f"Downloaded {no_of_bytes_downloaded} bytes of the file ",style="bold orange3")


class StorageNotConfigured(Exception):
    """The storage credentials or region are not set."""


def _s3_client():
    aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY")
    region_name = storage_region()
    if not aws_access_key_id or not aws_secret_access_key or not region_name:
        raise StorageNotConfigured("AWS credentials are not set")
    kwargs = {
        "aws_access_key_id": aws_access_key_id,
        "aws_secret_access_key": aws_secret_access_key,
        "region_name": region_name,
    }
    endpoint = storage_endpoint()
    if endpoint:
        kwargs["endpoint_url"] = endpoint
    return boto3.client("s3", **kwargs)

def upload_file(
    file_handle : any ,
    bucket : str | None = None,
    extension : str = ".zip",
    file_name : str = None,
    ):
    """Store ``file_handle`` in the upload bucket (``S3_BUCKET``, default ``devsecshield-storage``).

    Returns ``{"bucket": bucket, "object_name": object_name}``. Raises :class:`StorageUnavailable` (HTTP 503) when the
    upload fails; the AWS error code, the bucket and the endpoint are logged at error level (never the keys).
    """
    bucket = bucket or storage_bucket()
    object_name = file_name or (
        "file-" + str(datetime.now().strftime("%Y%m%d%H%M%S%f")) + "-" + str(uuid.uuid4())[:8] + extension)
    try:
        s3_client = _s3_client()
        s3_client.upload_fileobj(Fileobj=file_handle, Bucket=bucket, Key=object_name, ExtraArgs=None,
                                 Callback=show_upload_progress, Config=None)
    except StorageNotConfigured:
        logger.error("storage upload failed: aws_code=NotConfigured bucket=%s region=%s endpoint=%s "
                     "(AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / S3_REGION or AWS_DEFAULT_REGION missing)",
                     bucket, storage_region() or "-", storage_endpoint() or "aws")
        raise StorageUnavailable("NotConfigured") from None
    except Exception as e:
        code = _aws_code(e)
        http = (e.response or {}).get("ResponseMetadata", {}).get("HTTPStatusCode") if isinstance(e, ClientError) \
            else None
        logger.error("storage upload failed: aws_code=%s http_status=%s error_class=%s bucket=%s region=%s endpoint=%s",
                     code, http or "-", type(e).__name__, bucket, storage_region() or "-",
                     storage_endpoint() or "aws")
        console.print(f"Error uploading file: aws_code={code} bucket={bucket}", style="bold red", markup=False)
        raise StorageUnavailable(code) from e
    return {
        "bucket": bucket,
        "object_name": object_name
    }

def download_file(bucket : str, object_name : str):
    try:
        # STEP [ 1 ] : =========================== create a s3 client ========================================
        console.print(f"Creating a s3 client",style="bold yellow")
        s3_client = _s3_client()

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

