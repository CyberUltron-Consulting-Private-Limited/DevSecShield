from backend.new_models import scan_types
from backend.utilities.db.functions import StartScanPayload

def get_scan_metadata_for_type(scan_type: scan_types , start_scan_payload: StartScanPayload) -> dict:
    """
    Given a scan type and scan start data, return the scan metadata.
    Arguments :
    - type : scan_types
    - scan_start_data : dict | None
    Returns :
    -  dict ( scan metadata )
    
    """
    #TODO : Implement this function
    pass