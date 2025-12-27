import json
import subprocess
import tempfile
from typing import Literal
from urllib.parse import quote

from rich.console import Console

console = Console()


def run_wapiti(
    target_url:str,
    attack_modules : list[Literal[
        "common", "all", "backup", "brute_login_form", "buster", "cms", "crlf", "csrf",
        "exec", "file", "htaccess", "htp", "ldap", "log4shell", "methods", "network_device",
        "nikto", "permanentxss", "redirect", "shellshock", "spring4shell", "sql", "ssl",
        "ssrf", "takeover", "timesql", "upload", "wapp", "wp_enum", "xss", "xxe"
    ]] = ["common"], 
    max_scan_time : int = 60,
    user_agent : str | None = None,
    headers : list[dict] | None = None,
    cookies : list[dict] | None = None,
    scan_force : Literal[ "paranoid", "sneaky", "polite", "normal", "aggressive", "insane"] = "normal",
    exclude_url_patterns : list[str] | None = None,
):
    try :
        console.print(f"Running wapiti for the target url: {target_url}")
        # STEP [ 1 ] ==================== Building the basic command with output configured ============================================\
        temp_json_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        attack_modules_string = ",".join(attack_modules) if len(attack_modules) > 1 else attack_modules[0]
        cmd = [
            "uv",
            "run",
            "wapiti",
            "-u", target_url,
            "-f", "json",
            "-o", temp_json_file.name,
            "-m", attack_modules_string,
            "--flush-attacks",
            "--max-scan-time", str(max_scan_time),

        ]

        # STEP [ 2 ] ==================== Adding user agent, scan force and other basic options if provided ============================================
        if user_agent:
            console.print(f"Adding user agent: {user_agent}")
            cmd.extend(["--user-agent", user_agent])
        if scan_force:
            console.print(f"Adding scan force: {scan_force}")
            cmd.extend(["--scan-force", scan_force])
        

        # STEP [ 3 ] ==================== Adding headers and cookies if provided ============================================
        if headers and len(headers) > 0:
            header_string = []
            for header in headers:
                console.print(f"Adding header: {header}")
                header_string.append(f"{header['name']}: {header['value']}")
            
            if len(header_string) > 1:
                cmd.extend(["--header", ";".join(header_string)])
            else:
                cmd.extend(["--header", header_string[0]])


        if cookies and len(cookies) > 0:
            cookie_string = []
            for cookie in cookies:
                console.print(f"Adding cookie: {cookie}")
                cookie_string.append(f"{cookie['name']}={cookie['value']}")
            
            if len(cookie_string) > 1:
                cmd.extend(["--cookie", ";".join(cookie_string)])
            else:
                cmd.extend(["--cookie", cookie_string[0]])

        # STEP [ 4 ] ==================== Adding exclude url patterns if provided ============================================
        if exclude_url_patterns and len(exclude_url_patterns) > 0:
            for pattern in exclude_url_patterns:
                console.print(f"Adding exclude url pattern: {pattern}")
                cmd.extend(["-x", pattern])
            

        # STEP [ 5 ] ==================== Running the command ============================================
        console.print(f"Running the command: {cmd}")
        result = subprocess.run(cmd)


        # STEP [ 6 ] =================== Read the results from the temporary json file ============================================
        with open(temp_json_file.name, "r", encoding="utf-8", errors="ignore") as f:
            wapiti_json = json.load(f)


        return wapiti_json
    except Exception as e :
        raise Exception(f"Error in running wapiti: {e}")
    finally :
        temp_json_file.close()


if __name__ == "__main__":
    wapiti_json = run_wapiti(
        target_url="http://localhost:8000/api/items",
        attack_modules=["all"],
        max_scan_time=60,
        headers=[
            {
                "name": "Authorization",
                "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJOaWtoaWwiLCJleHAiOjE3NjY4MjIxNjYsInR5cGUiOiJhY2Nlc3MifQ.01Ks9UqErlQbuMohGFgwK8puOcXH38Y26HMe0NgqEyE"
            }
        ],
        user_agent="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.153 Safari/537.36 SE 2.X MetaSr 1.0",
        scan_force="insane",
    )
    with open("wapiti_test.json", "w+", encoding="utf-8") as f:
        json.dump(wapiti_json, f, indent=2)
