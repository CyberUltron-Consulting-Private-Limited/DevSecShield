from backend.get_db import get_mongo_client_db , dev_environment
from backend.mongo_models import ScanFindings



def get_findings_for_scan_id(scan_id: int) -> list[dict]:
    
    mongo_db = get_mongo_client_db(dev_environment)
    findings_collection = mongo_db["scan_findings"]

    findings = findings_collection.find({"scan_id": scan_id})

    findings_list = []
    for finding in findings:
        findings_list.append(finding)
    
    return findings_list