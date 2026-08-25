from helpers.agent.BaseUtilities import BaseUtilities
from helpers.agent.BaseSummaryManager import BaseSummaryManager
from helpers.schema import FinalVulnResponse , DASTVulnerability
from langchain_core.documents import Document
from helpers.agent.agent_graph import build_graph, OverallState
from rich.console import Console
console = Console(markup=False)

class SQLiAgent(BaseUtilities):

    def __init__(
        self,
        target_url : str,
        page_content : str,
        auth_login_template : str,
        exploit_retries : int = 2,
        validation_retries : int = 2,
        nuclei_timeout_seconds : int = 90,
        ):


        self.target_url = target_url
        self.page_content = page_content
        self.exploit_retries = exploit_retries
        self.validation_retries = validation_retries
        self.nuclei_timeout_seconds = nuclei_timeout_seconds
        self.strategy_generation_system_prompt = """
        You are a cybersecurity expert who is tasked with testing a Web application for SQLi vulnerabilities.
        You will be given the HTML page source of the website and you must generate a strategy for generating a **headless** nuclei template to test for SQLi vulnerabilities in the web application .
        Do not make the strategy too long , keep it concise and to the point . It must inform exactly what the nuclei template must do to exploit the SQLi vulnerability .
        """
        self.strategy_generation_prompt = """ 
        ## HTML Page Source :
        {page_content}
        """
        self.nuclei_template_generation_system_prompt = f"""
        You are a cybersecurity expert who is tasked with testing a Web application for SQLi vulnerabilities.
        You will be given a strategy based on which you must generate a headless nuclei template to test for SQLi vulnerabilities in the web application .
        Note: You must include the following actions listed below in the nuclei template since they allow you to authenticate yourself to the web application , navigate to the target page and execute the SQLi payload :
        Authentication and Navigation Nuclei Headless template :
        {auth_login_template}
        Note: 
        1. Use this template only to get the headless steps to login and navigate to the target page . Do not use this template as is . You must append it with your SQLi attack actions as described in the strategy provided .
        2. You must use the exact urls and xpaths provided in this auth + navigate template as is . Do not change them .
        3. This template is going to be run directly on the target page , so it must be a valid headless nuclei template that can be run directly on the target page .
        4. You must Insert your headless xss payload injection logic where the placeholder is specified in the template .\
        5. Make sure you use severity as high in the nuclei template .
        6. Make sure you employ appropriate matchers and extractors to report your findings 
        7. use a non destructive SQLi payload that is commonly used for educational purposes and not for exploitation .
        """
        self.nuclei_template_generation_prompt = """
        ## Strategy :
        {strategy}
        """
        self.nuclei_template_validation_system_prompt = """
        You are a YAML file validator who is tasked with validating a YAML file.
        You will be given YAML file content and you must check to see if it has anything other than valid YAML syntax , it should not contain anything other than the content that will be written to a .yaml file
        This YAML file content that you will be given is supposed to be ready to be directly used by nuclei to test for XSS vulnerabilities , keeping that in mind validate the YAML file content to see if it is a valid nuclei template that can be run directly on the target page .
        """
        self.nuclei_template_validation_prompt = """
        ## YAML File Content :
        {template}
        """
        self.summary_manager = SQLiSummaryManager()
    

    def run_sqli_agent_graph(self):
        try:
            console.print(f"▶️ Starting SQLi Agent Graph",style="bold green")
            graph = build_graph()
            initial_overall_state : OverallState = {
                "target_url" : self.target_url,
                "page_content" : self.page_content,
                "strategy_generation_system_prompt" : self.strategy_generation_system_prompt,
                "strategy_generation_prompt" : self.strategy_generation_prompt,
                "nuclei_template_generation_system_prompt" : self.nuclei_template_generation_system_prompt,
                "nuclei_template_generation_prompt" : self.nuclei_template_generation_prompt,
                "nuclei_template_validation_system_prompt" : self.nuclei_template_validation_system_prompt,
                "nuclei_template_validation_prompt" : self.nuclei_template_validation_prompt,
                "summary_manager" : self.summary_manager,


                # states to be updated by nodes
                "exploit_retries_left" : self.exploit_retries,
                "current_strategy" : None,
                "current_template" : None, # YAML file content for the headless nuclei template
                "template_valid" : False,
                "validation_retries_left" : self.validation_retries,
                "template_validation_reason" : None,
                "vulnerabilities" : [],
                "nuclei_timeout_seconds" : self.nuclei_timeout_seconds,
            }
            overall_state : OverallState = graph.invoke(initial_overall_state)

            vulnerabilities : list[DASTVulnerability] = overall_state["vulnerabilities"]
            console.print(f"✅ SQLi Agent Graph completed successfully",style="bold green")
            console.print(f"Number of vulnerabilities found: {len(vulnerabilities)}",style="dim green")
            console.print("======"*10,style="dim cyan")

            return vulnerabilities

        except Exception as e:
            raise Exception(f"Error in building graph: {e}")




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
**You are an DAST SQLi Vulnerability expert , analyze this HTML of the web page and extract the DAST SQLi Vulnerabilities from this HTML which can help a cybersecurity professional identify vulnerabilities later** . 
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
\n\n
---------------------------------------------------------------------------------------------------------------------------------------------------------------
## DAST Vulnerabilities  :
{text}
---------------------------------------------------------------------------------------------------------------------------------------------------------------

"""



class SQLiSummaryManager(BaseSummaryManager):
    def __init__(self):
        
        super().__init__(
            summary_output_model=FinalVulnResponse,
            refine_prompt_string = RefinePrompt,
            map_prompt_string = MapPrompt,
            combine_prompt_string = CombinePrompt,
            summary_starting_string="SQLi Vulnerabilities Identified in the web page are as follows : \n\n",
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
                Category: {vulnerability.category} \n
                Confidence: {vulnerability.confidence} \n
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
                Document Content : {document.page_content}\n
                =======================================================
                \n\n\n\n 
                """

            return documents_data
        except Exception as e:
            raise ValueError(f"Error in formatting documents to string: {e}")

