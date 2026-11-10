from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from rich.console import Console
from helpers.checks.security_headers import SecurityHeadersCheck
from helpers.crawler.crawler import Crawler
from helpers.agent.BaseTest import BaseTest
from helpers.schema import FinalVulnResponse, DASTVulnerability
from helpers.agent.xss_agent import XSSAgent
from helpers.agent.sqli_agent import SQLiAgent
from helpers.checks.page_analysis import PageAnalysisCheck
from helpers.progress_writer import StateUpdateWriter
from helpers.agent.context import StartDASTScanData, AuthRequirements
import time
from helpers.agent.base_vuln import parse_vuln_list
from helpers.agent.scan_config import ScanRuntime
from helpers.agent.utils import fetch_authenticated_page, get_auth_login_template
from helpers.checks.nuclei.run_nuclei import reap_orphan_browsers, set_nuclei_concurrency
console = Console(markup=False)

# Checks whose failure is recorded per URL. A check that could not run is not "no findings": when one of them failed
# on every scanned URL the scan cannot be reported as a clean "Completed" (found on the local stack, round 5: with
# Amazon Bedrock unavailable every XSS, SQLi and page-analysis check raised, each was logged and turned into an empty
# list, and Juice Shop came back "Completed, 0 findings, coverage 100%").
CHECK_LABELS = {
    "headers": "security headers",
    "page": "page analysis",
    "xss": "XSS",
    "sqli": "SQL injection",
}


class DastChecksDidNotRun(Exception):
    """One or more checks failed on every URL of the scan; the message names them and the first error of each."""



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
        self.runtime = ScanRuntime.from_speed(dast_context.scan_speed)
        self.interval_between_requests = self.runtime.interval_between_requests
        set_nuclei_concurrency(self.runtime.nuclei_concurrency)
    
        self.vulnerabilities : list[dict] = []
        self.metadata = {}
        self.urls = []
        self.state_update_writer = state_update_writer
        # check -> {url: first error message}; written from the URL worker threads
        self.check_errors: dict[str, dict[str, str]] = {name: {} for name in CHECK_LABELS}
        self._errors_lock = threading.Lock()

        if not self.auth_requirements.username or not self.auth_requirements.password or not self.auth_requirements.xpath_of_username_field or not self.auth_requirements.xpath_of_password_field or not self.auth_requirements.xpath_of_submit_button:
            raise Exception("Username, password, xpath of username field, xpath of password field, and xpath of submit button are required for authentication")

        # checks 
        self.checks : list[BaseTest] = []


    def _attach_url(self, parsed_vulnerabilities: list[dict], url: str) -> list[dict]:
        for parsed_vulnerability in parsed_vulnerabilities:
            parsed_vulnerability["url"] = url
        return parsed_vulnerabilities

    def _run_headers(self, url: str) -> list[dict]:
        try:
            security_headers_check = SecurityHeadersCheck(
                url=url,
                vulnerability_model=FinalVulnResponse,
                timeout=self.runtime.http_timeout_seconds,
            )
            security_headers_output : type[FinalVulnResponse] = security_headers_check.run()
            parsed = parse_vuln_list(security_headers_output.vulnerabilities)
            console.print(f"Security headers check completed for {url}",style="bold green")
            console.print(f"Number of vulnerabilities found: {len(parsed)}",style="bold green")
            return self._attach_url(parsed, url)
        except Exception as e:
            console.print(f"Error in security headers check for {url}: {e}",style="dim red")
            self._record_check_error("headers", url, e)
            return []

    def _fetch_page(self, url: str):
        try:
            return fetch_authenticated_page(
                url,
                self.auth_requirements,
                timeout_seconds=self.runtime.nuclei_timeout_seconds,
            )
        except Exception as e:
            console.print(f"Error fetching page content for {url}: {e}",style="dim red")
            return "", []

    def _run_page_analysis(self, url: str, documents) -> list[dict]:
        try:
            page_analysis_check = PageAnalysisCheck(url=url,auth=self.auth_requirements)
            vulnerabilities : list[DASTVulnerability] = page_analysis_check.run(
                documents=documents,
                timeout_seconds=self.runtime.nuclei_timeout_seconds,
            )
            parsed = parse_vuln_list(vulnerabilities or [])
            console.print(f"Page analysis check completed for {url}",style="bold green")
            console.print(f"Number of vulnerabilities found: {len(parsed)}",style="bold green")
            return self._attach_url(parsed, url)
        except Exception as e:
            console.print(f"Error in page analysis check for {url}: {e}",style="dim red")
            self._record_check_error("page", url, e)
            return []

    def _run_xss(self, url: str, page_content: str, auth_login_template: str) -> list[dict]:
        try:
            if page_content is None:
                raise Exception("page content unavailable")
            xss_agent = XSSAgent(
                target_url=url,
                page_content=page_content,
                auth_login_template=auth_login_template,
                exploit_retries=self.runtime.exploit_retries,
                validation_retries=self.runtime.validation_retries,
                nuclei_timeout_seconds=self.runtime.nuclei_timeout_seconds,
            )
            vulnerabilities : list[DASTVulnerability] = xss_agent.run_xss_agent_graph()
            parsed = parse_vuln_list(vulnerabilities)
            console.print(f"XSS check completed for {url}",style="bold green")
            console.print(f"Number of vulnerabilities found: {len(parsed)}",style="bold green")
            return self._attach_url(parsed, url)
        except Exception as e:
            console.print(f"Error in XSS check for {url}: {e}",style="dim red")
            self._record_check_error("xss", url, e)
            return []

    def _run_sqli(self, url: str, page_content: str, auth_login_template: str) -> list[dict]:
        try:
            if page_content is None:
                raise Exception("page content unavailable")
            sqli_agent = SQLiAgent(
                target_url=url,
                page_content=page_content,
                auth_login_template=auth_login_template,
                exploit_retries=self.runtime.exploit_retries,
                validation_retries=self.runtime.validation_retries,
                nuclei_timeout_seconds=self.runtime.nuclei_timeout_seconds,
            )
            vulnerabilities : list[DASTVulnerability] = sqli_agent.run_sqli_agent_graph()
            parsed = parse_vuln_list(vulnerabilities)
            console.print(f"SQLi check completed for {url}",style="bold green")
            console.print(f"Number of vulnerabilities found: {len(parsed)}",style="bold green")
            return self._attach_url(parsed, url)
        except Exception as e:
            console.print(f"Error in SQLi check for {url}: {e}",style="dim red")
            self._record_check_error("sqli", url, e)
            return []

    def _record_check_error(self, check: str, url: str, error: Exception) -> None:
        with self._errors_lock:
            self.check_errors[check].setdefault(url, str(error).replace("\n", " ")[:300])

    def _checks_that_never_ran(self) -> list[str]:
        """Checks that failed on every scanned URL."""
        if not self.urls:
            return []
        return [name for name, by_url in self.check_errors.items() if len(by_url) >= len(self.urls)]

    def _judge_checks(self) -> None:
        """Record partial check failures in the metadata; refuse to report a scan whose checks did not run."""
        partial = {name: len(by_url) for name, by_url in self.check_errors.items() if by_url}
        if partial:
            self.metadata["check_errors"] = {"urls_scanned": len(self.urls), "failed_urls_per_check": partial}
        never = self._checks_that_never_ran()
        if never:
            reasons = "; ".join(
                f"{CHECK_LABELS[name]}: {next(iter(self.check_errors[name].values()))}" for name in never
            )
            raise DastChecksDidNotRun(
                f"The scan could not run its {', '.join(CHECK_LABELS[n] for n in never)} check(s) on any of the "
                f"{len(self.urls)} URLs, so its results would be incomplete ({reasons[:600]})"
            )

    def _report_progress(self, completed: int, total: int):
        if not self.state_update_writer or total <= 0:
            return
        pct = 30 + int(69 * completed / total)
        self.state_update_writer.write_progress_percentage(min(pct, 99))
        self.state_update_writer.write_progress_out_of_total(completed, total)

    def _scan_url(self, url: str) -> list[dict]:
        started = time.time()
        found: list[dict] = []
        with ThreadPoolExecutor(max_workers=2) as pool:
            headers_future = pool.submit(self._run_headers, url)
            page_future = pool.submit(self._fetch_page, url)
            found.extend(headers_future.result())
            page_content, documents = page_future.result()

        auth_login_template = ""
        try:
            auth_login_template = get_auth_login_template(url, self.auth_requirements)
        except Exception as e:
            console.print(f"Error building auth template for {url}: {e}", style="dim red")

        with ThreadPoolExecutor(max_workers=3) as pool:
            page_future = pool.submit(self._run_page_analysis, url, documents)
            xss_future = pool.submit(self._run_xss, url, page_content or "", auth_login_template)
            sqli_future = pool.submit(self._run_sqli, url, page_content or "", auth_login_template)
            found.extend(page_future.result())
            found.extend(xss_future.result())
            found.extend(sqli_future.result())

        if self.runtime.interval_between_requests:
            time.sleep(self.runtime.interval_between_requests)
        elapsed = time.time() - started
        console.print(
            f"URL completed in {elapsed:.1f}s findings={len(found)} url={url}",
            style="bold yellow1",
        )
        return found


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
            urls = list(dict.fromkeys(crawler.crawl()))
            metadata = crawler.metadata
            console.print(f"Scanning {len(urls)} unique URLs", style="bold yellow1")
            console.print(
                f"Scan runtime speed workers={self.runtime.url_workers} "
                f"checks={self.runtime.check_workers} nuclei_slots={self.runtime.nuclei_concurrency} "
                f"interval={self.runtime.interval_between_requests}s "
                f"nuclei_timeout={self.runtime.nuclei_timeout_seconds}s "
                f"all_stages=headers,nuclei,page,xss,sqli",
                style="bold yellow1",
            )
            if not len(urls)>0 : 
                raise Exception("No Urls to crawl") 

            self.metadata = metadata
            self.urls = urls

            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(30)

            
            # STEP [ 3 ] : ----------------------- Cycle through each url and run the checks ----------------------------------------

            workers = max(1, min(self.runtime.url_workers, len(self.urls)))
            completed = 0
            if workers == 1:
                for url in self.urls:
                    self.vulnerabilities.extend(self._scan_url(url))
                    completed += 1
                    self._report_progress(completed, len(self.urls))
            else:
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = {pool.submit(self._scan_url, url): url for url in self.urls}
                    for future in as_completed(futures):
                        url = futures[future]
                        try:
                            self.vulnerabilities.extend(future.result())
                        except Exception as e:
                            console.print(f"Error scanning {url}: {e}", style="dim red")
                        completed += 1
                        self._report_progress(completed, len(self.urls))

            
            # STEP [ 4 ] : ----------------------- Return the Vulnerabilities ----------------------------------------
            self._judge_checks()
            if self.state_update_writer:
                self.state_update_writer.write_progress_percentage(100)

            
            return self.vulnerabilities , self.metadata
            
        except Exception as e:
            console.print(f"Error in running DAST agent: {e}",style="dim red")
            raise e
        finally:
            reap_orphan_browsers() 
    

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
