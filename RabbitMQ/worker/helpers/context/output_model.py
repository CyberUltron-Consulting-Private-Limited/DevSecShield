from rich.console import Console
from helpers.context.schema import BaseVulnerability, CodebaseVulnerability, DependencyVulnerability, LLMBenchmarkingVulnerability
from pydantic import BaseModel, Field , create_model
from typing import Annotated, Literal
import urllib.parse
import requests
import time
from enum import Enum
from helpers.context.schema import FallbackCVEEnum

console = Console()

class OutputModelManager:

    def __init__(self):
        raise Exception("OutputModelManager is a singleton class and should not be instantiated")

    def get_codebase_output_model(self) -> type[BaseModel]:
        try:
            console.print(f"Getting Codebase Output Model ....",style="dim yellow")
            codebase_output_model = self.get_output_model(CodebaseVulnerability)
            console.print(f"Codebase Output Model generated successfully",style="bold green")
            return codebase_output_model
        except Exception as e:
            console.print(f"Error in getting codebase output model: {e}",style="dim red")
            raise e
    
    def get_dependency_output_model(self) -> type[BaseModel]:
        try:
            console.print(f"Getting Dependency Output Model ....",style="dim yellow")
            dependency_output_model = self.get_output_model(DependencyVulnerability)
            console.print(f"Dependency Output Model generated successfully",style="bold green")
            return dependency_output_model
        except Exception as e:
            console.print(f"Error in getting dependency output model: {e}",style="dim red")
            raise e
    
    def get_llm_benchmarking_output_model(self) -> type[BaseModel]:
        try:
            console.print(f"Getting LLM Benchmarking Output Model ....",style="dim yellow")
            llm_benchmarking_output_model = self.get_output_model(LLMBenchmarkingVulnerability)
            console.print(f"LLM Benchmarking Output Model generated successfully",style="bold green")
            return llm_benchmarking_output_model
        except Exception as e:
            console.print(f"Error in getting llm benchmarking output model: {e}",style="dim red")
            raise e
    
    def get_base_output_model(self) -> type[BaseModel]:
        try:
            console.print(f"Getting Base Output Model ....",style="dim yellow")
            base_output_model = self.get_output_model(BaseVulnerability)
            console.print(f"Base Output Model generated successfully",style="bold green")
            return base_output_model
        except Exception as e:
            console.print(f"Error in getting base output model: {e}",style="dim red")
            raise e

    def get_output_model(self, VulnerabilityModel : type[BaseVulnerability] | type[CodebaseVulnerability]) -> type[BaseModel]:
        try:
            console.print(f"Getting Output Model ....",style="dim yellow")
            cves_dict = self.fetch_recent_cves()
            cves_enum = self.create_CVE_enum(cves_dict)
            output_model = self.create_output_model(cves_enum, VulnerabilityModel)
            console.print(f"Output Model generated successfully",style="bold green")
            return output_model
        except Exception as e:
            console.print(f"get_output_model failed , generating fallback output model: {e}",style="dim blue1")
            fallback_output_model = self.create_fallback_output_model(VulnerabilityModel)
            console.print(f"Fallback Output Model generated successfully",style="bold green")
            return fallback_output_model

    def create_CVE_enum(self,cves: dict[str, str]) -> Enum:
        try:
            DynamicEnum = Enum('DynamicEnum', cves)
            enum_members = list(DynamicEnum.__members__.keys())
            console.print(f"CVE Enum Members: {enum_members}",style="dim bright_cyan")
            return DynamicEnum
        except Exception as e:
            console.print(f"Error in creating CVE enum: {e}",style="dim red")
            return None
    
    
    def fetch_cves_for_year(
        self,
        year : str = "2025",
        limit: int = 30,
        severity: Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] = 'CRITICAL',
        max_retries : int = 3,
        retry_delay : int = 5,
        verbose : bool = False,
        ) -> dict[str, str]:
        try:
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

            #converting dates to ISO8601 format
            year_string = f"CVE-{year}"
            params = {
                "keywordSearch": year_string,
                "cvssV3Severity": severity,
                "resultsPerPage": limit,
            }
            url = base_url + "?" + urllib.parse.urlencode(params)
            if verbose:
                console.print(f"URL: {url}",style="dim yellow")
            response = requests.get(url)
            if response.status_code == 429: # rate limit exceeded
                console.print(f"Rate limit exceeded, retrying in 5 seconds",style="dim red")
                for i in range(max_retries):
                    time.sleep(retry_delay)
                    response = requests.get(url) # retrying the request
                    if response.status_code == 200:
                        break # breaking the loop early if the request retry is successful



            # ⭐ The only place where the error is GET request error is handled 
            if response.status_code != 200:
                raise Exception(f"Error in fetching CVE: {response.status_code}")
            
            data = response.json()
            cves = data["vulnerabilities"]
            console.print(f"CVE data fetched successfully for year {year} , number of CVEs: {len(cves)}",style="dim yellow")


            cves_dict = {}
            for item in cves:
                english_description = None
                cve = item["cve"]
                for description in cve["descriptions"]:
                    if description["lang"] == "en":
                        english_description = description["value"]
            
                        if verbose:
                            print(cve["id"])
                            print(description["lang"])
                            print(description["value"])
                            print("--------------------------------")

                cves_dict[cve["id"]] = english_description if english_description else "No description available"
            
            return cves_dict
        except Exception as e:
            console.print(f"Error in fetching CVE for year: {e}",style="dim red")
            raise e
    
    
    
    def fetch_recent_cves(
        self,
        years : list[int] = [2025 , 2026],
        ) -> dict[str, str]:
        try:
            cves_dict = {}
            for year in years:
                cves_dict.update(self.fetch_cves_for_year(year=str(year)))
            console.print(f"Recent CVEs fetched successfully, number of CVEs: {len(cves_dict)}",style="dim yellow")
            return cves_dict
        except Exception as e:
            console.print(f"Error in fetching recent CVEs: {e}",style="dim red")
            raise e
    
    def create_output_model(self,cves_enum: Enum, VulnerabilityModel : type[BaseVulnerability] | type[CodebaseVulnerability] | type[LLMBenchmarkingVulnerability]) -> type[BaseModel]:
        try:
            console.print(f"Creating Output Model ....",style="dim yellow")
            
            # --------------------------------------- ⭐ Final Vulnerability Model ---------------------------------------
            final_vulnerability_model_fields = {}
            # for f_name, f_info in VulnerabilityModel.model_fields.items():
            #     f_dct = f_info.asdict()
            #     final_vulnerability_model_fields[f_name] = (
            #         Annotated[f_dct['annotation'] , *f_dct['metadata'], Field(**f_dct['attributes'])],
            #     )
            final_vulnerability_model_fields["cves"] = ( list[cves_enum],  Field(description="A list of CVE vulnerabilities that this vulnerability is related to") )
            
            FinalVulnerabilityModel = create_model(
                "FinalVulnerabilityModel",
                __base__ = VulnerabilityModel,
                **final_vulnerability_model_fields
            )
            console.print(f"Final Vulnerability Model created successfully",style="dim green")
            
            # --------------------------------------- ⭐ Final Output Model ---------------------------------------
            response_model_fields = {}
            response_model_fields["vulnerabilities"] = (
                list[FinalVulnerabilityModel], Field(description="List of vulnerabilities found , return empty list if no vulnerabilities found")
            )
            ResponseModel = create_model(
                "ResponseModel",
                __base__=BaseModel,
                **response_model_fields
            )
            
            console.print(f"Response Model created successfully",style="bold green")
            return ResponseModel
        except Exception as e:
            console.print(f"Error in creating output model,: {e}",style="dim red")
            raise e

    def create_fallback_output_model(self, VulnerabilityModel : type[BaseVulnerability] | type[CodebaseVulnerability]) -> type[BaseModel]:
        try:
            console.print(f"Creating Fallback Output Model ....",style="dim yellow")
            class FinalVulnerabilityModel(VulnerabilityModel):
                cves : list[FallbackCVEEnum] = Field(description="A list of CVE vulnerabilities that this vulnerability is related to")
            
            attributes = [attribute for attribute in FinalVulnerabilityModel.__pydantic_fields__.keys()]
            expected_attributes = ["title", "description", "impact", "owasp_top_10", "suggested_fix"]
            for attribute in expected_attributes:
                if attribute in attributes:
                    continue
                else:
                    raise Exception(f"Attribute {attribute} is missing from the output model")
            console.print(f"Final Vulnerability Model created successfully",style="dim green")
            
            # ⭐ Final Output Model
            class ResponseModel(BaseModel):
                vulnerabilities : list[FinalVulnerabilityModel] = Field(description="List of vulnerabilities found , return empty list if no vulnerabilities found")
            
            console.print(f"Response Model created successfully",style="bold green")
            return ResponseModel
        except Exception as e:
            console.print(f"Error in creating fallback output model,: {e}",style="dim red")
            raise e