import urllib
import datetime
import time
import uuid
from zapv2 import ZAPv2
from dotenv import load_dotenv
import os
from typing import Literal
from rich.console import Console

console = Console()


def is_timed_out(
    start_time: datetime.datetime,
    timeout_duration_mins: int,
) -> bool:
    this_instant = datetime.datetime.now()
    total_seconds = (this_instant - start_time).total_seconds()
    m, s = divmod(total_seconds, 60)
    minutes = int(m)
    seconds = int(s)
    Console().print(f"Elapsed time : {minutes} Minutes , {seconds} Seconds")
    if minutes >= timeout_duration_mins:
        Console().print("Timed out!", style="bold red")
        return True
    else:
        return False


def run_zap_scan_with_form_auth(
    target_url: str,
    login_url: str,
    zap_daemon_proxy_url: str = "http://localhost:8090",
    include_urls: list[str] = [],
    exclude_urls: list[str] = [],
    mode: Literal["St-Low-Th-High", "API", "API-Minimal", "Pen Test", "QA Standard"] = "Pen Test",
    timeout_durations_mins: int = 20,
    poll_durations_seconds: int = 5,
    username_value: str = "test@example.com",
    password_value: str = "weakPassword",
    username_key: str = "username",
    password_key: str = "password",
    logged_in_regex: str = "\\Q<a href=\"logout.php\">Logout</a>\\E",
    logged_out_regex: str = "(?:Location: [./]*login\\.php)|(?:\\Q<form action=\"login.php\" method=\"post\">\\E)",
) -> dict:
    """
    Run ZAP active scan with form-based authentication.
    
    This function performs all necessary steps:
    1. Initializes ZAP client
    2. Creates context and configures include/exclude URLs
    3. Sets up form-based authentication method
    4. Configures logged in/out indicators
    5. Creates user with authentication credentials
    6. Enables forced user mode
    7. Runs spider scan
    8. Runs active scan
    9. Returns scan results
    
    Args:
        target_url: Target URL to scan
        login_url: URL of the login page
        zap_daemon_proxy_url: ZAP daemon proxy URL (default: "http://localhost:8090")
        include_urls: List of URLs to include in context
        exclude_urls: List of URLs to exclude from context
        mode: Scan policy mode (default: "Pen Test")
        timeout_durations_mins: Timeout duration in minutes (default: 20)
        poll_durations_seconds: Poll interval in seconds (default: 5)
        username_value: Username value for authentication
        password_value: Password value for authentication
        username_key: Form field name for username (default: "username")
        password_key: Form field name for password (default: "password")
        user: Display name for the user (default: "Test User")
        logged_in_regex: Regex pattern to detect logged in state
        logged_out_regex: Regex pattern to detect logged out state
        
    Returns:
        dict: Scan results (alerts)
    """
    try:
        # STEP [ 1 ] ============================================== Initialize ZAP Client ==================================================================================
        # Load API Key
        load_dotenv()
        api_key = os.getenv("ZAP_API_KEY")
        if not api_key:
            raise Exception("API Key not provided to access ZAP")

        # Initialize ZAP Client
        zap = ZAPv2(apikey=api_key, proxies={'http': zap_daemon_proxy_url, 'https': zap_daemon_proxy_url})
        
        
        # STEP [ 2 ] ======================================================= Configure Context ==================================================================================
        # Create context
        context_name = "context-" + str(uuid.uuid4()) + "-" + str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f"))
        context_id = zap.context.new_context(context_name)
        console.print(f'Created context: {context_name} (ID: {context_id})', style="bold green")
        
        # Configure include and exclude URLs in context
        if len(include_urls) <= 0 or include_urls is None:
            include_urls = [f"{target_url}.*"]
        for include_url in include_urls:
            zap.context.include_in_context(context_name, include_url)
        for exclude_url in exclude_urls:
            zap.context.exclude_from_context(context_name, exclude_url)
        console.print('Configured include and exclude regex(s) in context', style="bold green")
        
        # Setup form-based authentication
        # Format: username={%username%}&password={%password%}
        login_request_data = f'{username_key}={{%{username_key}%}}&{password_key}={{%{password_key}%}}'
        form_based_config = f'loginUrl={urllib.parse.quote(login_url)}&loginRequestData={urllib.parse.quote(login_request_data)}'
        zap.authentication.set_authentication_method(context_id, 'formBasedAuthentication', form_based_config)
        console.print('Configured form based authentication', style="bold green")
        
        # Setup logged in/out indicators
        zap.authentication.set_logged_in_indicator(context_id, logged_in_regex)
        zap.authentication.set_logged_out_indicator(context_id, logged_out_regex)
        console.print('Configured logged in/out indicator regex', style="bold green")
        
        # Create user and set authentication credentials
        user = "User_" + str(uuid.uuid4()) + "_" + str(datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f"))
        user_id = zap.users.new_user(context_id, user)
        
        # Format: username=test@example.com&password=weakPassword
        user_auth_config = f'{username_key}={urllib.parse.quote(username_value)}&{password_key}={urllib.parse.quote(password_value)}'
        zap.users.set_authentication_credentials(context_id, user_id, user_auth_config)
        zap.users.set_user_enabled(context_id, user_id, 'true')
        console.print('User Auth Configured', style="bold green")
        
        # Enable forced user mode
        zap.forcedUser.set_forced_user(context_id, user_id)
        zap.forcedUser.set_forced_user_mode_enabled('true')
        console.print('Forced user mode enabled', style="bold green")
        
        
        # STEP [ 3 ] ======================================================= Run Spider Scan ==================================================================================
        
        # Run Spider Scan
        console.print('Spidering target {} as user {}'.format(target_url, user_id), style="bold yellow")
        start_time = datetime.datetime.now()
        scanID = zap.spider.scan_as_user(
            contextid=context_id, 
            userid=user_id, 
            url=target_url, 
            recurse='true',
            apikey=api_key
        )

        if scanID == "does_not_exist":
                raise Exception("Spider scan didn't initiate successfully")
        # Poll the status until it completes
        while int(zap.spider.status(scanID)) < 100:
            if is_timed_out(start_time=start_time, timeout_duration_mins=timeout_durations_mins):
                break
            console.print(f"Spider scan {scanID} progress : {zap.spider.status(scanID)} %", style="bold blue1")
            time.sleep(poll_durations_seconds)
        
        # Prints the URLs the spider has crawled
        urls_crawled = list(map(str, zap.spider.results(scanID)))
        console.print(f"A total of {len(urls_crawled)} were found in the spider scan", style="bold yellow")
        
        # STEP [ 4 ] ======================================================= Run Active Scan ==================================================================================
        start_time = datetime.datetime.now()
        console.print(f"Active Scanning target {target_url} in {mode} mode", style="bold yellow")
        
        # Run the active scan
        scanID = zap.ascan.scan_as_user(
            contextid=context_id, 
            userid=user_id, 
            url=target_url, 
            scanpolicyname=mode,
            apikey=api_key
        )
        
        if scanID == "does_not_exist":
                raise Exception("Active scan didn't initiate successfully")
        # Poll the status until it completes
        while int(zap.ascan.status(scanID)) < 100:
            if is_timed_out(start_time=start_time, timeout_duration_mins=timeout_durations_mins):
                break
            console.print(f"Active scan {scanID} progress : {zap.ascan.status(scanID)} %", style="bold blue1")
            time.sleep(poll_durations_seconds)
        
        # Pause the scan
        zap.ascan.pause(scanid=scanID, apikey=api_key)
        console.print('Active Scan completed', style="bold green")
        
        # STEP [ 5 ] ======================================================= Get scan results ==================================================================================

        try:
            scan_results = zap.alert.alerts(baseurl=target_url, contextname=context_name)
            console.print(f"Scan results successfully got using context name {context_name}", style="bold green")
            return scan_results
        except Exception as e:
            console.print(f"An Error occurred while getting scan results using context name in the API : {str(e)}", style="bold red")
            pass
        
        try:
            scan_results = zap.core.alerts(baseurl=target_url)
            console.print(f"Scan results successfully got using baseurl {target_url}", style="dim green")
            return scan_results
        except Exception as e:
            console.print(f"An Error occurred while getting scan results using baseurl in the API : {str(e)}", style="bold red")
            raise Exception(f"An Error occurred while getting scan results using baseurl in the API : {str(e)}")
        
    except Exception as e:
        console.print(f"An Error occurred during ZAP Scan : {str(e)}", style="bold red")
        raise e


if __name__ == "__main__":
    """
    Test case for BodgeIt application with form-based authentication.
    
    Prerequisites:
    1. Start BodgeIt application:
       docker run --rm -p 8091:8080 -i -t psiinon/bodgeit
       
    2. Start ZAP in daemon mode:
       zap.sh -daemon -port 8090 -config api.key=your_api_key
       (or set ZAP_API_KEY in .env file)
    
    3. Ensure BodgeIt is accessible at http://localhost:8091/bodgeit/
    """
    import json
    
    # BodgeIt application configuration
    target_url = "https://0ffea5a0ecd8.ngrok-free.app/bodgeit/"
    login_url = "https://0ffea5a0ecd8.ngrok-free.app/bodgeit/login.jsp"
    
    # BodgeIt default credentials
    username_value = "test@gmail.com"
    password_value = "weakPass"
    
    # BodgeIt form field names
    username_key = "username"
    password_key = "password"
    
    # Logged in/out indicators for BodgeIt
    # Logged in: User info or welcome message appears
    logged_in_regex = "\\QWelcome\\E|\\QUser Info\\E|\\QLogout\\E"
    # Logged out: Login form appears
    logged_out_regex = "\\Qlogin.jsp\\E|\\Q<form.*login\\E"
    
    console.print("=" * 80, style="bold cyan")
    console.print("Starting ZAP Scan Test for BodgeIt Application", style="bold cyan")
    console.print("=" * 80, style="bold cyan")
    console.print(f"Target URL: {target_url}", style="bold yellow")
    console.print(f"Login URL: {login_url}", style="bold yellow")
    console.print(f"Username: {username_value}", style="bold yellow")
    console.print("=" * 80, style="bold cyan")
    
    try:
        # Run the scan
        results = run_zap_scan_with_form_auth(
            target_url=target_url,
            login_url=login_url,
            include_urls=[f"{target_url}.*"],
            exclude_urls=[],
            mode="Pen Test",
            timeout_durations_mins=30,
            poll_durations_seconds=5,
            username_value=username_value,
            password_value=password_value,
            username_key=username_key,
            password_key=password_key,
            logged_in_regex=logged_in_regex,
            logged_out_regex=logged_out_regex,
        )
        
        # Save results to file
        output_file = "bodgeit_scan_results.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        
        console.print("=" * 80, style="bold green")
        console.print(f"Scan completed successfully!", style="bold green")
        console.print(f"Results saved to: {output_file}", style="bold green")
        console.print(f"Total alerts found: {len(results)}", style="bold green")
        console.print("=" * 80, style="bold green")
        
        # Print summary of alerts by risk level
        if results:
            risk_counts = {}
            for alert in results:
                risk = alert.get("risk", "Unknown")
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
            
            console.print("\nAlert Summary by Risk Level:", style="bold cyan")
            for risk, count in sorted(risk_counts.items()):
                console.print(f"  {risk}: {count}", style="bold yellow")
        
    except Exception as e:
        console.print("=" * 80, style="bold red")
        console.print(f"Test failed with error: {str(e)}", style="bold red")
        console.print("=" * 80, style="bold red")
        raise

