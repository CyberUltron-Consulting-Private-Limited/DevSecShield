from helpers.schema import FinalVulnResponse
from helpers.agent.BaseTest import BaseTest
from helpers.checks.nuclei.construct_temp import construct_login_template , construct_navigate_template , construct_navigate_action , construct_xss_template
from rich.console import Console
from helpers.agent.context import AuthRequirements
import tempfile
from helpers.checks.nuclei.run_nuclei import run_nuclei
from helpers.agent.BaseUtilities import BaseUtilities
from helpers.agent.BaseSummaryManager import BaseSummaryManager
from langchain_core.documents import Document
from helpers.agent.base_vuln import parse_vuln_list

console = Console(markup=False)


class XSSCheck(BaseTest,BaseUtilities):

    def __init__(self, url: str , auth: AuthRequirements):
        self.url = url
        self.auth = auth



        self.login_url = auth.login_url
        self.xpath_of_username_field = auth.xpath_of_username_field
        self.xpath_of_password_field = auth.xpath_of_password_field
        self.username = auth.username
        self.password = auth.password
        self.xpath_of_submit_button = auth.xpath_of_submit_button




    def run(self):
        """
        Run the page analysis check
        """
        try :

            new_login_template = construct_login_template(self.auth)
            new_navigate_action = construct_navigate_action(self.url)
            new_xss_template = construct_xss_template(self.xss_input_field_xpath, self.xss_submit_button_xpath)

            new_xss_template = new_login_template + new_navigate_action + new_xss_template

            # for testing 
            with open("new_xss_template.yaml", "w+") as f:
                f.write(new_xss_template)
            
            temp_yaml_file = tempfile.NamedTemporaryFile(delete=False,suffix=".yaml")

            with open(temp_yaml_file.name, "w+") as f:
                f.write(new_xss_template)
            

            result = run_nuclei(self.url,temp_yaml_file.name)


            self.documents = result

            summary : type[FinalVulnResponse] = self.generate_map_reduce_summary(
                summary_manager=PageAnalysisSummaryManager()
                )
            
            vulns = summary.vulnerabilities
            parsed_vulns : list[dict] = parse_vuln_list(vulns)

            for vuln in parsed_vulns:
                vuln["url"] = self.url

            return parsed_vulns # list[dict ( DASTVulnerability )]

        except Exception as e:
            console.print(f"Error while running page analysis check: {e}",style="bold red")
            return None



RefinePrompt = """
## Your Task : \n
Refine the given DAST Vulnerabilities list to make it more coherent and detailed . 
\n\n
---------------------------------------------------------------------------------------------------------
### The existing DAST Vulnerabilities list that needs to be refined is  :\n
{summary} 
\n\n\n
----------------------------------------------------------------------------------------------------------- 
### Here is the new content that must be used to refine the existing DAST Vulnerabilities list :\n
{text}
\n
----------------------------------------------------------------------------------------------------------
"""

MapPrompt = """
## Your Task : \n
**You are an IAC Vulnerability expert , analyze this HTML of the web page and extract the DAST Vulnerabilities from this HTML which can help a cybersecurity professional identify vulnerabilities later** . 
Important : Extract at most 2 DAST Vulnerabilities from this HTML but meake the description as detailed as possible for each DAST Vulnerability , capturing all the logic/workflows corresponding to each DAST Vulnerability .
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## HTML of the web page :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------
"""
CombinePrompt = """
## Your Task : \n
Analyze the DAST Vulnerabilities provided below that have been extracted from the HTML of the web page and combine them into a single list of DAST Vulnerabilities.
Important : Combine at most 3 DAST Vulnerabilities into a single DAST Vulnerability , making the description as detailed as possible for each DAST Vulnerability , capturing all the logic/workflows corresponding to each DAST Vulnerability .
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## DAST Vulnerabilities  :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------

"""


class PageAnalysisSummaryManager(BaseSummaryManager):
    
    def __init__(self):



        output_model = FinalVulnResponse
        
        super().__init__(
            summary_output_model=output_model,
            refine_prompt_string = RefinePrompt,
            map_prompt_string = MapPrompt,
            combine_prompt_string = CombinePrompt,
            summary_starting_string="DAST Vulnerabilities Identified in the HTML of the web page are as follows : \n\n",
        )

    
        
    def format_to_string(
        self, 
        input:type[FinalVulnResponse] )->str:
        """
        Responsible for formatting the summary output model to a string
        Returns:
            str
        """
        try:

            output_model_string = ""
            for vulnerability in input.vulnerabilities:
                temp = f"""
                \n\n
                =======================================================================================
                Title: {vulnerability.title} \n
                Description: {vulnerability.description} \n
                Impact: {vulnerability.impact} \n
                OWASP Top 10: {vulnerability.owasp_top_10} \n
                Compliance Controls: {vulnerability.compliance_controls} \n
                Suggested Fix: {vulnerability.suggested_fix} \n
                category: {vulnerability.category.value} \n
                confidence: {vulnerability.confidence.value} \n
                =======================================================================================
                \n\n
                """
                output_model_string += temp
            
            final_string = self.summary_starting_string + output_model_string

            # console.print(f"Formatted string length {len(final_string)} and content is {final_string[:300]}...",style="dim yellow")
            return final_string
        except Exception as e:
            raise ValueError(f"Error in formatting summary output model to string: {e}")
    
    def format_documents_to_string(
        self,
        documents:list[Document],
        )->str:
        """
        Responsible for formatting the documents into a string
        """
        try:
            documents_data = ""
            for document in documents:
                documents_data += f"""
                =======================================================
                HTML of the web page : {document.page_content}\n
                =======================================================
                \n\n\n\n 
                """

            return documents_data
        except Exception as e:
            raise ValueError(f"Error in formatting documents to string: {e}")
