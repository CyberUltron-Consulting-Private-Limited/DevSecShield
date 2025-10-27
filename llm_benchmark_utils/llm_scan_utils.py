from enum import Enum
from pydantic import BaseModel, Field
from ..utilities import generate_structured_response





def llm_owasp_tracker(probe_name:str,results:dict,detector_name:str):

    class OWASPTop10(Enum):
        BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
        CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
        INJECTION = "A03:2021 - Injection"
        INSECURE_DESIGN = "A04:2021 - Insecure Design"
        SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
        VULNERABLE_AND_OUTDATED_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
        IDENTIFICATION_AND_AUTHENTICATION_FAILURES = "A07:2021 - Identification and Authentication Failures"
        SOFTWARE_AND_DATA_INTEGRITY_FAILURES = "A08:2021 - Software and Data Integrity Failures"
        SECURITY_LOGGING_AND_MONITORING_FAILURES = "A09:2021 - Security Logging and Monitoring Failures"
        SERVER_SIDE_REQUEST_FORGERY = "A10:2021 - Server-Side Request Forgery (SSRF)"

    class OWASPTop10_Response(BaseModel):
        risk : OWASPTop10 = Field(description="The name of the OWASP top 10 Vulnerability that this threat causes")
        description : str = Field(description="A detailed description of how why this vulnerability was found for this threat")

    class OWASP_Response(BaseModel):
        tracker_data: list[OWASPTop10_Response] = Field(description="The list of OWASP top 10 Vulnerabilities found in the System overall")
    
    system_prompt = """You are a cybersecurity professional and you will be given,
    a probe used to scan an LLM model and the results of the scan.
    You need to return the list of OWASP top 10 Vulnerabilities that were found in the system.
    """
    
    prompt=f"""
    Probe: {probe_name}
    Detector: {detector_name}
    Results: {results}
    """
    response = generate_structured_response(prompt=prompt,system_prompt=system_prompt,output_model=OWASP_Response)

    result = [ { "risk":item["risk"].value, "description":item["description"] } for item in response.model_dump()["tracker_data"] ]
    print(f"🟨 OWASP Response: {result}")

    return result
    

def llm_compliance_tracker(probe_name:str,results:dict,detector_name:str):
    
    class Compliance(BaseModel):
        control : str = Field(description="The compliance control that fails because of this threat")
        description : str = Field(description="A detailed description of how the control fails because of this threat")

    class Compliance_Response(BaseModel):
        tracker_data: list[Compliance] = Field(description="The list of Compliance Vulnerabilities found in the System overall")
    
    system_prompt = """You are a cybersecurity professional and you will be given,
    a probe used to scan an LLM model and the results of the scan.
    You need to return the list of Compliance Vulnerabilities that were found in the system.
    """
    prompt=f"""
    Probe: {probe_name}
    Detector: {detector_name}
    Results: {results}
    """
    response = generate_structured_response(prompt=prompt,system_prompt=system_prompt,output_model=Compliance_Response)
    return response.model_dump()["tracker_data"]
    
def llm_probe_fix(probe_name:str,results:dict,detector_name:str,model_type:str,model_name:str):
    
    class Fix(BaseModel):
        fix: str = Field(description="The fix for the probe")
    
    system_prompt = """You are a cybersecurity professional and you will be given,
    a probe used to scan an LLM model and the results of the scan.
    You need to return the fix for the probe."""

    prompt=f"""
    Probe: {probe_name}
    Detector: {detector_name}
    Results: {results}
    Model Type: {model_type}
    Model Name: {model_name}
    """
    print(f"🟨 Prompt: {prompt}")
    response = generate_structured_response(prompt=prompt,system_prompt=system_prompt,output_model=Fix)
    return response.model_dump()["fix"]

if __name__ == "__main__":
    # Test case for llm_owasp_tracker function
    test_probe_name = "malwaregen.Evasion"
    test_detector_name = "malwaregen.AnyCode"
    test_results = {
        "passed": 35,
        "total": 48,
        "hit_rate": 27.08
    }
    
    print("🟨 Testing llm_owasp_tracker function...")
    print(f"Probe: {test_probe_name}")
    print(f"Detector: {test_detector_name}")
    print(f"Results: {test_results}")
    print()
    
    try:
        owasp_data = llm_owasp_tracker(
            probe_name=test_probe_name,
            results=test_results,
            detector_name=test_detector_name
        )
        
        print("🟩 OWASP Tracker Test Results:")
        print(f"Number of OWASP vulnerabilities found: {len(owasp_data)}")
        for i, vulnerability in enumerate(owasp_data, 1):
            print(f"{i}. {vulnerability}")
        
    except Exception as e:
        print(f"🟥 Test failed with error: {str(e)}")
