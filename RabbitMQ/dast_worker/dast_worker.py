from typing import Literal
from celery import Celery
from rich.console import Console
from dotenv import load_dotenv
import os
import sys
import json
from wapiti import run_wapiti
from zap import run_zap_scan_with_form_auth
#====================================== Setting credentials to connect to broker ================================================================
console = Console()

os.environ["IS_DOCKER_CONTAINER"] = "False"  # ⚠️⚠️⚠️⚠️⚠️⚠️⚠️

#====================================== Setting credentials to connect to broker ================================================================
try:
    load_dotenv()
    is_docker_container = os.getenv("IS_DOCKER_CONTAINER")
    if is_docker_container and is_docker_container == "True":
        username = os.getenv("RABBIT_ADMIN_USERNAME")
        password = os.getenv("RABBIT_ADMIN_PASSWORD")

        mongo_username = os.getenv("MONGO_INITDB_ROOT_USERNAME")
        mongo_password = os.getenv("MONGO_INITDB_ROOT_PASSWORD")
        mongo_host = "13.203.233.15"
        mongo_port = "27017"
        mongo_url = f"mongodb://{mongo_username}:{mongo_password}@{mongo_host}:{mongo_port}/"
        if not username or not password  or not mongo_username or not mongo_password: 
            raise Exception("Username, password or mongo username or password not set")
        
        broker_url = f"amqp://{username}:{password}@13.203.233.15:5672"
    else:
        username = os.getenv("RABBIT_ADMIN_USERNAME")
        password = os.getenv("RABBIT_ADMIN_PASSWORD")


        mongo_url = os.getenv("RABBIT_MONGO_CONNECTION_URL")
        if not username or not password or not mongo_url: 
            raise Exception("Username, password or mongo url not set")

        broker_url = f"amqp://{username}:{password}@localhost:5672"
    
except Exception as e :
    console.print(f"Error in getting credentials: {e}",style="dim red")
    sys.exit()




#============================================================== Registering tasks to worker ==================================================================== 

try:
    # app = Celery('worker', broker=f"amqp://{username}:{password}@localhost:5672",backend='rpc://')
    app = Celery('dast_worker', broker=broker_url,backend=mongo_url)
    app.conf.update(
        RESULT_PERSISTENT=True,
        TASK_TRACK_STARTED=True,
    )
    Console().print(f"Celery App instantiated",style="bold green")


    
    @app.task(track_started=True)
    def wapiti_dast(
        target_url: str,
        additional_urls: list[str] = [],
        attack_modules: list[Literal["common", "all", "backup", "brute_login_form", "buster", "cms", "crlf", "csrf", "exec", "file", "htaccess", "htp", "ldap", "log4shell", "methods", "network_device", "nikto", "permanentxss", "redirect", "shellshock", "spring4shell", "sql", "ssl", "ssrf", "takeover", "timesql", "upload", "wapp", "wp_enum", "xss", "xxe"]] = ["common"],
        max_scan_time: int = 60,
        user_agent: str | None = None,
        headers: list[dict] | None = None,
        cookies: list[dict] | None = None,
        scan_force: Literal["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"] = "normal",
        exclude_url_patterns: list[str] | None = None,
        ):
        """
        Header inputs should look like : 
        [
            {
                "name": "Authorization",
                "value": "Bearer 1234567890"
            }
        ]
        Cookie inputs should look like : 
        [
            {
                "name": "session",
                "value": "1234567890"
            }
        ]
        """
        try:
            results = run_wapiti(
                target_url=target_url,
                additional_urls=additional_urls,
                attack_modules=attack_modules,
                max_scan_time=max_scan_time,
                user_agent=user_agent,
                headers=headers,
                cookies=cookies,
                scan_force=scan_force,
                exclude_url_patterns=exclude_url_patterns,
            )
            Console().print(f"DAST scan completed successfully",style="bold green")
            return results
        except Exception as e:
            Console().print(f"Error in dast task: {str(e)}",style="bold red")
            raise e
    Console().print(f"Registered Wapiti DAST task ",style="bold green")


    @app.task(track_started=True)
    def zap_dast(
         target_url: str,
        login_url: str,
        include_urls: list[str] = [],
        exclude_urls: list[str] = [],
        timeout_durations_mins: int = 20,
        poll_durations_seconds: int = 5,
        username_value: str = "test@example.com",
        password_value: str = "weakPassword",
        username_key: str = "username",
        password_key: str = "password",
        logged_in_regex: str = "\\Q<a href=\"logout.php\">Logout</a>\\E",
        logged_out_regex: str = "(?:Location: [./]*login\\.php)|(?:\\Q<form action=\"login.php\" method=\"post\">\\E)",
    ):
        """
        Run form based DAST scan using ZAP
        """
        try:
            results = run_zap_scan_with_form_auth(
                target_url=target_url,
                login_url=login_url,
                include_urls=include_urls,
                exclude_urls=exclude_urls,
                timeout_durations_mins=timeout_durations_mins,
                poll_durations_seconds=poll_durations_seconds,
                username_value=username_value,
                password_value=password_value,
                username_key=username_key,
                password_key=password_key,
                logged_in_regex=logged_in_regex,
                logged_out_regex=logged_out_regex,
            )
            Console().print(f"ZAP DAST scan completed successfully",style="bold green")
            return results
        except Exception as e:
            Console().print(f"Error in zap dast task: {str(e)}",style="bold red")
            raise e

except Exception as e:
    Console().print(f"Error occured while registering tasks : {str(e)}",style="bold red")
    sys.exit()