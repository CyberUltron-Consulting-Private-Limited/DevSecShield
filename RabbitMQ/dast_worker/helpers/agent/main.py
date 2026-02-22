from rich.console import Console
from helpers.checks.security_headers import SecurityHeadersCheck
from helpers.crawler.crawler import Crawler
from helpers.agent.BaseTest import BaseTest
from helpers.schema import FinalVulnResponse, DASTVulnerability
from helpers.agent.xss_agent import XSSAgent
from helpers.agent.sqli_agent import SQLiAgent
from helpers.checks.page_analysis import PageAnalysisCheck
from helpers.progress_writer import StateUpdateWriter
from typing import Literal
from helpers.agent.context import StartDASTScanData, AuthRequirements
import time
from helpers.agent.base_vuln import parse_vuln_list
from helpers.agent.utils import get_page_content , get_auth_login_template
console = Console()



class DASTAgent():


    def __init__(
        self,
        dast_context: StartDASTScanData,
        state_update_writer: StateUpdateWriter | None = None,
        ):



        self.url = dast_context.target_url
        self.max_urls = dast_context.max_urls
        self.additional_urls_to_scan = dast_context.additional_urls_to_scan
        self.include_url_patterns = dast_context.include_url_patterns
        self.exclude_url_patterns = dast_context.exclude_url_patterns
        self.auth_requirements : AuthRequirements = dast_context.auth
    
        self.vulnerabilities : list[dict] = []
        self.metadata = {}
        self.urls = []
        self.state_update_writer = state_update_writer

        if dast_context.scan_speed == "fast":
            self.interval_between_requests = 5 # seconds 
        elif dast_context.scan_speed == "medium":
            self.interval_between_requests = 10 # seconds 
        elif dast_context.scan_speed == "slow":
            self.interval_between_requests = 15 # seconds 

        if not self.auth_requirements.username or not self.auth_requirements.password or not self.auth_requirements.xpath_of_username_field or not self.auth_requirements.xpath_of_password_field or not self.auth_requirements.xpath_of_submit_button:
            raise Exception("Username, password, xpath of username field, xpath of password field, and xpath of submit button are required for authentication")

        # checks 
        self.checks : list[BaseTest] = []



    def run(self):
        """
        1. run crawl with filters and additonal urls to scan 
        2. for each url, run the following steps :
            ( each check generates vulns that gets appended to the vulns list )
            a. run security header check ( tested and working  ✅) 
            b. run xss check
            c. run sql injection check
            d. run page analysis check 
        3. return the vulns list with metadata 
        """
        try :
            # STEP [ 1 ] : ----------------------- Run Crawler ----------------------------------------
            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(10)

            crawler = Crawler(
                url=self.url,
                max_urls=self.max_urls,
                additional_urls_to_scan=self.additional_urls_to_scan,
                include_url_patterns=self.include_url_patterns,
                exclude_url_patterns=self.exclude_url_patterns,
            )
            urls = crawler.crawl()
            metadata = crawler.metadata
            if not len(urls)>0 : 
                raise Exception("No Urls to crawl") 

            self.metadata = metadata
            self.urls = urls

            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(30)

            
            # STEP [ 3 ] : ----------------------- Cycle through each url and run the checks ----------------------------------------

            for url in self.urls:
                # Step 1 : security headers Chech 
                security_headers_check = SecurityHeadersCheck(url=url,vulnerability_model=FinalVulnResponse)
                security_headers_output : type[FinalVulnResponse] = security_headers_check.run()
                vulnerabilities = security_headers_output.vulnerabilities
                parsed_vulnerabilities = parse_vuln_list(vulnerabilities)
                for parsed_vulnerability in parsed_vulnerabilities:
                    parsed_vulnerability["url"] = url
                self.vulnerabilities.extend(parsed_vulnerabilities)
                console.print(f"Security headers check completed for {url}",style="bold green")
                console.print(f"Number of vulnerabilities found: {len(parsed_vulnerabilities)}",style="bold green")


                # Step 2 : page analysis check 
                page_analysis_check = PageAnalysisCheck(url=url,auth=self.auth_requirements)
                vulnerabilities : list[DASTVulnerability] = page_analysis_check.run()
                parsed_vulnerabilities = parse_vuln_list(vulnerabilities)
                for parsed_vulnerability in parsed_vulnerabilities:
                    parsed_vulnerability["url"] = url
                self.vulnerabilities.extend(parsed_vulnerabilities)
                console.print(f"Page analysis check completed for {url}",style="bold green")
                console.print(f"Number of vulnerabilities found: {len(parsed_vulnerabilities)}",style="bold green")


                # Step 3 : XSS check 
                page_content = get_page_content(url,self.auth_requirements)
                auth_login_template = get_auth_login_template(url,self.auth_requirements)
                xss_agent = XSSAgent(target_url=url,page_content=page_content,auth_login_template=auth_login_template)
                vulnerabilities : list[DASTVulnerability] = xss_agent.run_xss_agent_graph()
                parsed_vulnerabilities = parse_vuln_list(vulnerabilities)
                for parsed_vulnerability in parsed_vulnerabilities:
                    parsed_vulnerability["url"] = url
                self.vulnerabilities.extend(parsed_vulnerabilities)
                console.print(f"XSS check completed for {url}",style="bold green")
                console.print(f"Number of vulnerabilities found: {len(parsed_vulnerabilities)}",style="bold green")


                # Step 4 : SQLi check 
                sqli_agent = SQLiAgent(target_url=url,page_content=page_content,auth_login_template=auth_login_template)
                vulnerabilities : list[DASTVulnerability] = sqli_agent.run_sqli_agent_graph()
                parsed_vulnerabilities = parse_vuln_list(vulnerabilities)
                for parsed_vulnerability in parsed_vulnerabilities:
                    parsed_vulnerability["url"] = url
                self.vulnerabilities.extend(parsed_vulnerabilities)
                console.print(f"SQLi check completed for {url}",style="bold green")
                console.print(f"Number of vulnerabilities found: {len(parsed_vulnerabilities)}",style="bold green")

                time.sleep(self.interval_between_requests) # sleep for the interval between requests  

            

            # STEP [ 4 ] : ----------------------- Return the Vulnerabilities ----------------------------------------
            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(100)

            
            return self.vulnerabilities , self.metadata
            
        except Exception as e:
            console.print(f"Error in running DAST agent: {e}",style="dim red")
            raise e 
    

    def estimate_credits(self):
        try:
            crawler = Crawler(
                    url=self.url,
                    max_urls=self.max_urls,
                    additional_urls_to_scan=self.additional_urls_to_scan,
                    include_url_patterns=self.include_url_patterns,
                    exclude_url_patterns=self.exclude_url_patterns,
            )
            urls = crawler.crawl()

            if not len(urls)>0 : 
                raise Exception("No Urls to crawl") 

            self.urls = urls

            if not len(self.urls)>0 : 
                return -1 
            
            total_credits = len(self.urls) * 0.08 # 0.08 credits per url
            return total_credits
    
        except Exception as e:
            console.print(f"Error in estimating credits: {e}",style="dim red")
            return -1 