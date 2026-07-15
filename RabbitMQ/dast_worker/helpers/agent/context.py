from pydantic import BaseModel
from typing import Literal

class AuthRequirements(BaseModel):
    login_url: str | None = None
    xpath_of_username_field: str | None = None
    xpath_of_password_field: str | None = None
    username: str | None = None
    password: str | None = None
    xpath_of_submit_button: str | None = None

class StartDASTScanData(BaseModel):
    """
    Both include and exclude url patterns are not going to be used together
    """
    target_url: str
    auth: AuthRequirements 
    scan_speed : Literal["fast" , "medium" , "slow"] = "medium"
    max_urls: int = 100
    additional_urls_to_scan: list[str] | None = None # these urls will be scanned definitely 
    exclude_url_patterns: list[str] | None = None # either exclude urls that match these patterns or include urls that match these patterns
    include_url_patterns: list[str] | None = None # either exclude urls that match these patterns or include urls that match these patterns
