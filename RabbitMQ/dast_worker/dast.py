import urllib
import datetime
import time
from zapv2 import ZAPv2
from dotenv import load_dotenv
import os
from typing import Literal
from rich.console import Console
console = Console()


def is_timed_out(
    start_time:datetime.datetime,
    timeout_duration_mins:int,
    )->bool:
    this_instant = datetime.datetime.now()
    total_seconds = (this_instant - start_time).total_seconds()
    m, s = divmod(total_seconds, 60) 
    minutes = int(m)
    seconds = int(s)
    Console().print(f"Elapsed time : {minutes} Minutes , {seconds} Seconds")
    if minutes >= timeout_duration_mins :
        Console().print("Timed out!",style="bold red")
        return True
    else:
        return False

class DASTBot():

    def __init__(
        self , 
        target_url:str,
        zap_daemon_proxy_url:str = "http://localhost:8090",
        include_urls : list[str] = [],
        exclude_urls : list[str] = [],
        mode:Literal["St-Low-Th-High" , "API" , "API-Minimal" , "Pen Test" , "QA Standard"] = "Pen Test",
        timeout_durations_mins:int=20,
        poll_durations_seconds:int=5,
        ):

        # -----------------------------------------------------Load API Key--------------------------------------------------------
        load_dotenv()
        apiKey = os.getenv("ZAP_API_KEY")
        if not apiKey:
            raise Exception("API Key not provided to access ZAP")

        # -----------------------------------------------------Initialize ZAP Client and set the attributes--------------------------------------------------------
        self.api_key = apiKey
        self.target_url = target_url
        self.zap_daemon_proxy_url = zap_daemon_proxy_url
        self.include_urls = include_urls
        self.exclude_urls = exclude_urls
        self.mode = mode
        self.timeout_durations_mins = timeout_durations_mins
        self.poll_durations_seconds = poll_durations_seconds
        
        # ----------------------------------------------form based auth related attributes ( initialized to None )-----------------------------------------------
        self.username_key = None
        self.password_key = None
        self.username_value = None
        self.password_value = None
        self.login_url = None

        # mock values for context
        self.context_name = "default"
        self.context_id = 1

    
    def __initialize_zap_client(self)->ZAPv2:
        
        zap = ZAPv2(apikey=self.api_key, proxies={'http': self.zap_daemon_proxy_url, 'https': self.zap_daemon_proxy_url})
        return zap
    
    
    def __setup_form_based_authentication(
        self,
        zap:ZAPv2,
        login_url:str,
        username_value:str = "test@example.com",
        password_value:str = "weakPassword",
        username_key:str = "username",
        password_key:str = "password",
        )-> ZAPv2:

        # example : username={%username%}&password={%password%}
        login_request_data = self.username_key + '={%' + self.username_key + '%}&' + self.password_key + '={%' + self.password_key + '%}'


        form_based_config = 'loginUrl=' + urllib.parse.quote(login_url) + '&loginRequestData=' + urllib.parse.quote(login_request_data)
        zap.authentication.set_authentication_method(self.context_id, 'formBasedAuthentication', form_based_config)
        console.print('Configured form based authentication',style="bold green")
        return zap

    def __setup_logged_in_and_out_regex(
        self,
        zap:ZAPv2,
        logged_in_regex:str = "\\Q<a href=\"logout.php\">Logout</a>\\E",
        logged_out_regex:str = "(?:Location: [./]*login\\.php)|(?:\\Q<form action=\"login.php\" method=\"post\">\\E)",
        )-> ZAPv2:

        zap.authentication.set_logged_in_indicator(self.context_id, logged_in_regex)
        zap.authentication.set_logged_out_indicator(self.context_id, logged_out_regex)
        console.print('Configured logged in indicator regex ',style="bold green")

        return zap
    
    def __setup_user_for_form_based_authentication(
        self,
        zap:ZAPv2,
        user:str = "Test User",
        username_value:str = "test@example.com",
        password_value:str = "weakPassword",
        )-> ZAPv2:
        
        user_id = zap.users.new_user(self.context_id, user)
        self.user_id = user_id # store the user id for future use

        # example : username=test@example.com&password=weakPassword
        user_auth_config = f'{self.username_key}=' + urllib.parse.quote(username_value) + f'&{self.password_key}=' + urllib.parse.quote(password_value)


        zap.users.set_authentication_credentials(self.context_id, user_id, user_auth_config)
        zap.users.set_user_enabled(self.context_id, user_id, 'true')
        zap.forcedUser.set_forced_user(self.context_id, user_id)
        zap.forcedUser.set_forced_user_mode_enabled('true')

        console.print('User Auth Configured',style="bold green")
        
        return zap
    
    def set_context(self)-> ZAPv2:
        """
        Setup context for Spider + Active scan 

        1. setup form based authentication
        2. setup context for auth method 
        3. add user for scanner to use

        """
        zap = self.__initialize_zap_client()
        
        # ----------------------------------------------include and exclude urls in context -----------------------------------------------------------
        for include_url in self.include_urls:
            zap.context.include_in_context(self.context_name, include_url)
        for exclude_url in self.exclude_urls:
            zap.context.exclude_from_context(self.context_name, exclude_url)
        console.print('Configured include and exclude regex(s) in context',style="bold green")

    
    
    def __run_spider_scan(self,zap:ZAPv2)-> ZAPv2:
        

        console.print('Spidering target {}'.format(self.target_url),style="bold yellow")
        start_time = datetime.datetime.now()
        scanID = zap.spider.scan_as_user(self.context_id, self.user_id, self.target_url, recurse='true')

        # Poll the status until it completes
        while int(zap.spider.status(scanID)) < 100:
            if is_timed_out(start_time=start_time , timeout_duration_mins=self.timeout_durations_mins ):
                break 
            if scanID == "does_not_exist":
                raise Exception("Spider scan didn't initiate successfully")
            # Poll the status until it completes
            console.print(f"Spider scan {scanID} progress : {zap.spider.status(scanID)} %",style="bold blue1")
            time.sleep(self.poll_durations_seconds)
        # Prints the URLs the spider has crawled
        urls_crawled = list(map(str, zap.spider.results(scanID)))
        console.print(f"A total of {len(urls_crawled)} were found in the spider scan",style="bold yellow")
        return zap

    def __run_active_scan(self)-> ZAPv2:
        
        try:
            start_time = datetime.datetime.now()
            console.print(f"Active Scanning target {self.target_url} in {self.mode} mode",style="bold yellow")

            # initialize zap client
            zap = self.__initialize_zap_client()

            # Run the active scan
            scanID = zap.ascan.scan_as_user(self.context_id, self.user_id, self.target_url, scanpolicyname=self.mode)

            # Poll the status until it completes
            while int(zap.ascan.status(scanID)) < 100:
                if is_timed_out(start_time=start_time , timeout_duration_mins=self.timeout_durations_mins ):
                    break 
                if scanID == "does_not_exist":
                    raise Exception("Active scan didn't initiate successfully")
                # Loop until the scanner has finished
                console.print(f"Active scan {scanID} progress : {zap.ascan.status(scanID)} %",style="bold blue1")
                time.sleep(self.poll_durations_seconds)

            # Pause the scan
            zap.ascan.pause(scanid=scanID,apikey=self.api_key) #⚠️
            console.print('Active Scan completed',style="bold green")

            return zap
            
        except Exception as e:
            console.print(f"An Error occured during Active Scan : {str(e)} ",style="bold red")
            raise e

    def run_scan(self)-> None:
        self.__setup_form_based_authentication()
        self.__setup_context_for_auth_method()
        self.__setup_user_for_form_based_authentication()
        self.__run_spider_scan()
        self.__run_active_scan()
        