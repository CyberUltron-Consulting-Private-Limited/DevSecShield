import subprocess 
import json
import tempfile
import shutil
from rich.progress import Progress,Task
def run_mcp_scan(server_config_path:str,progress:Progress,task:Task) -> list[dict]:

    try:
        # STEP : ------------------------------------------------------------Running the mcp-scan command----------------------------------------------------------
        progress.update(task, description=f"Starting the mcp-scan command for the server config path: {server_config_path} 🟨",advance=10)
        temp_dir = tempfile.mkdtemp()
        cmd=[ "uvx" , "mcp-scan" ,server_config_path, "--json" , "--opt-out" , "--full-toxic-flows","--storage-file", temp_dir ]
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        shutil.rmtree(temp_dir)

        # STEP : Checking if the command was successful
        if result.returncode != 0:
            raise Exception(f"Error: {result.stderr.decode('utf-8')}")
        
        # STEP : ------------------------------------------------------------Decoding the results----------------------------------------------------------
        progress.update(task, description=f"Decoding the results 🟨",advance=10)
        results = result.stdout.decode("utf-8")
        error = result.stderr.decode("utf-8")

        #   for testing
        # with open("mcp_results_2.json", "w+") as f:
        #     json.dump(results, f, indent=2)

        # STEP :----------------------------------------------------------Loading the results into a dictionary----------------------------------------------------------
        progress.update(task, description=f"Loading the results into a dictionary 🟨",advance=10)
        start_index = results.find("{") # because sometimes the scan prints an error message before the actual results , so we need to load the results from the start of the json object
        raw_scan_dict = json.loads(results[start_index:])

        #for testing
        # with open("mcp_results_2.json", "w+") as f:
        #     json.dump(raw_scan_dict, f, indent=2)

        
        # STEP : ---------Creating a indexable list of tools inside an indexable list of servers for each mapping with issues and vulnerabilities found in the server-------------
        progress.update(task, description=f"Creating a indexable list of tools inside an indexable list of servers for each mapping with issues and vulnerabilities found in the server 🟨",advance=10)
        list_of_tools_per_server = []
        
        servers = raw_scan_dict[server_config_path]["servers"]
        print(f"Number of servers found : {len(servers)} 🟩")
        for server in servers:
            server_tools = []
            server_name = server["name"]
            if error in server or server["signature"]==None:
                # error workflow
                continue
            tools = server["signature"]["tools"]
            for tool in tools:
                tool_name = tool["name"]
                tool_description = tool["description"]
                tool_input_schema = tool["inputSchema"]
                tool = {
                    "name": tool_name,
                    "description": tool_description.encode("utf-8").decode("utf-8"),
                    "input_schema": tool_input_schema
                }
                server_tools.append(tool)
            list_of_tools_per_server.append(server_tools)

        # STEP : ------------------------------Mapping the tools with the issues and vulnerabilities found in the server----------------------------------------
        progress.update(task, description=f"Mapping the tools with the issues and vulnerabilities found in the server 🟨",advance=10)
        final_issues = []
        issues = raw_scan_dict[server_config_path]["issues"]
        for issue in issues:
            issue_types = issue["extra_data"].keys()
            issue_code = issue["code"]
            issue_message = issue["message"]
            for issue_type in issue_types:
                issue_type_instance_list = issue["extra_data"][issue_type]
                for item in issue_type_instance_list:
                    if item["label_value"] < 1:
                        issue_severity = "unknown"
                    elif item["label_value"] == 1:
                        issue_severity = "low"
                    elif item["label_value"] == 2:
                        issue_severity = "high"
                    elif item["label_value"] == 3:
                        issue_severity = "critical"
                    elif item["label_value"] > 3:
                        issue_severity = "critical"
                    else:
                        issue_severity = "unknown"
                    issue_dict = {
                        "issue_code": issue_code,
                        "issue_message": issue_message,
                        "issue_type": issue_type,
                        "server": servers[item["reference"][0]]["name"],
                        "tool": list_of_tools_per_server[item["reference"][0]][item["reference"][1]],
                        "issue_severity": issue_severity
                    }
                    final_issues.append(issue_dict)
        print(f"Number of issues found : {len(final_issues)} 🟩")

        # for testing
        # with open("final_issues.json", "w+") as f:
        #     json.dump(final_issues, f, indent=2)

        progress.update(task, description=f"Finished the mcp-scan command for the server config path: {server_config_path} 🟩",advance=10)
        progress.update(task, completed=100)
        return final_issues
    
    except Exception as e:
        progress.update(task, description=f"Error occured while running the mcp-scan 🔴: {e}")
        progress.update(task, completed=100)
        return None

def run_mcp_scan_with_progress(server_config_path:str) -> list[dict]:
    with Progress() as progress:
        task = progress.add_task("Running the mcp-scan command", total=100)
        result = run_mcp_scan(server_config_path,progress,task)
    return result

if __name__ == "__main__":
    results = run_mcp_scan_with_progress(server_config_path="C:\\Users\\HP\\Desktop\\DevSecShield\\test-server-mcp.json")
    print(results[-1])

