import datetime
import json
import time
from pprint import pprint
from typing import Literal
from zapv2 import ZAPv2
from dotenv import load_dotenv
import os
from rich.console import Console


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

def run_ZAP(
    target_url:str,
    mode:Literal["St-Low-Th-High" , "API" , "API-Minimal" , "Pen Test" , "QA Standard"] = "Pen Test",
    timeout_durations_mins:int=20,
    poll_durations_seconds:int=5):

    try : 

        # -----------------------------------------------------Load API Key--------------------------------------------------------
        load_dotenv()
        apiKey = os.getenv("ZAP_API_KEY")
        if not apiKey:
            raise Exception("API Key not provided to access ZAP")

        # -----------------------------------------------------Initialize ZAP Client--------------------------------------------------------
        zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://localhost:8090', 'https': 'http://localhost:8090'})

        
        # -----------------------------------------------------Running Spider--------------------------------------------------------
        Console().print('Spidering target {}'.format(target_url),style="bold yellow")
        start_time = datetime.datetime.now()
        scanID = zap.spider.scan(target_url)
        while int(zap.spider.status(scanID)) < 100:
            if is_timed_out(start_time=start_time , timeout_duration_mins=timeout_durations_mins ):
                break 
            if scanID == "does_not_exist":
                raise Exception("Scan didn't initiate successfully")
            # Poll the status until it completes
            Console().print(f"Spider scan {scanID} progress : {zap.spider.status(scanID)} %",style="bold blue1")
            time.sleep(poll_durations_seconds)
        # Prints the URLs the spider has crawled
        urls_crawled = list(map(str, zap.spider.results(scanID)))
        Console().print(f"A total of {len(urls_crawled)} were found in the spider scan",style="bold yellow")



        # -----------------------------------------------------Active Scan-------------------------------------------------------
        zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})
        # TODO : explore the app (Spider, etc) before using the Active Scan API, Refer the explore section
        Console().print(f"Active Scanning target {target_url} in {mode} mode",style="bold yellow")
        scanID = zap.ascan.scan(url=target_url,scanpolicyname=mode)
        while int(zap.ascan.status(scanID)) < 100:
            if is_timed_out(start_time=start_time , timeout_duration_mins=timeout_durations_mins ):
                break 
            if scanID == "does_not_exist":
                raise Exception("Scan didn't initiate successfully")
            # Loop until the scanner has finished
            Console().print(f"Active scan {scanID} progress : {zap.ascan.status(scanID)} %",style="bold blue1")
            time.sleep(poll_durations_seconds)
        zap.ascan.pause(scanid=scanID,apikey=apiKey) #⚠️
        Console().print('Active Scan completed',style="bold green")


        # -----------------------------------------------------Getting results and performing cleanup tasks--------------------------------------------------------
        findings = zap.core.alerts(baseurl=target_url)
        zap.ascan.stop(scanid=scanID,apikey=apiKey) #⚠️

        # for testing 
        with open("testing.json","w+") as f:
            json.dump(findings,f)
        
        return findings
    
    except Exception as e:
        Console().print(f"An Error occured during ZAP Scan : {str(e)} ")
        raise e #⚠️ 


if __name__ == "__main__":
    run_ZAP(target_url='http://www.itsecgames.com/',mode="API-Minimal")
    # start = datetime.datetime.now()
    # time.sleep(60*2)
    # print(is_timed_out(start,1))
