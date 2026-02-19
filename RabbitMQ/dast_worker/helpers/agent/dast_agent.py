from rich.console import Console
from helpers.checks.security_headers import SecurityHeadersCheck
from helpers.crawler.crawler import Crawler
from helpers.agent.BaseTest import BaseTest
from helpers.schema import FinalVulnResponse, DASTVulnerability
from helpers.progress_writer import StateUpdateWriter
from typing import Literal
from helpers.agent.context import StartDASTScanData, AuthRequirements
import time
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
    
        self.vulnerabilities : list[DASTVulnerability] = []
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


            
            
            # STEP [ 2 ] : ----------------------------- Setup the Checks ------------------------------------------------------------
            
            self.checks.append(SecurityHeadersCheck(url=self.url,vulnerability_model=FinalVulnResponse))

            
            
            
            
            # STEP [ 3 ] : ----------------------- Cycle through each url and run the checks ----------------------------------------

            for url in self.urls:
                for check in self.checks:
                    output : type[FinalVulnResponse] = check.run()
                    self.vulnerabilities.extend(output.vulnerabilities)

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
            metadata = crawler.metadata
            if not len(urls)>0 : 
                raise Exception("No Urls to crawl") 

            # self.metadata = metadata
            self.urls = urls

            if not len(self.urls)>0 : 
                return -1 
            
            total_credits = len(self.urls) * 0.004 # 0.004 credits per url 
            return total_credits
    
        except Exception as e:
            console.print(f"Error in estimating credits: {e}",style="dim red")
            return -1 