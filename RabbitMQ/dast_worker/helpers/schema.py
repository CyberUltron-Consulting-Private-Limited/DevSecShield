from pydantic import BaseModel, Field
from helpers.enums import * 

class BaseVulnerability(BaseModel):
    title : str = Field(description="The title of the vulnerability")
    description : str = Field(description="The description of the vulnerability")
    impact : Impact = Field(description="The impact of the vulnerability")
    owasp_top_10 : list[OWASPTop10] = Field(description="A list of OWASP top 10 vulnerabilities that this vulnerability is related to")
    compliance_controls : list[ComplianceControls] = Field(description="A list of compliance controls that this vulnerability is related to")
    suggested_fix : str = Field(description="The suggested fix for the vulnerability")

class DASTVulnerability(BaseVulnerability):
    category : DASTVulnerabilityGroup = Field(description="The category of the finding")
    confidence : DASTConfidence = Field(description="The confidence of the finding")


class FinalVulnResponse(BaseModel):
    vulnerabilities : list[DASTVulnerability] = Field(description="A list of vulnerabilities")
    