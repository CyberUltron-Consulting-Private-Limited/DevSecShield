import subprocess 
import json
import tempfile
import shutil
from rich.progress import Progress,Task
from rich.console import Console
def run_mcp_scan(server_config_path:str) -> list[dict] | str:

    try:
        # STEP : ------------------------------------------------------------Running the mcp-scan command----------------------------------------------------------
        Console().print(f"Starting the mcp-scan command for the server config path: {server_config_path} 🟨",style="bold yellow")
        temp_dir = tempfile.mkdtemp()
        cmd=[ "uvx" , "mcp-scan" ,server_config_path, "--json" , "--opt-out" , "--full-toxic-flows","--storage-file", temp_dir ]
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        shutil.rmtree(temp_dir)

        # STEP : Checking if the command was successful
        if result.returncode != 0:
            raise Exception(f"Error: {result.stderr.decode('utf-8')}")
        
        # STEP : ------------------------------------------------------------Decoding the results----------------------------------------------------------
        Console().print(f"Decoding the results 🟨",style="bold yellow")
        results = result.stdout.decode("utf-8")
        error = result.stderr.decode("utf-8")

        #   for testing
        # with open("mcp_results_2.json", "w+") as f:
        #     json.dump(results, f, indent=2)

        # STEP :----------------------------------------------------------Loading the results into a dictionary----------------------------------------------------------
        Console().print(f"Loading the results into a dictionary 🟨",style="bold yellow")
        start_index = results.find("{") # because sometimes the scan prints an error message before the actual results , so we need to load the results from the start of the json object
        raw_scan_dict = json.loads(results[start_index:])

        # for testing
        with open("mcp_results_2.json", "w+") as f:
            json.dump(raw_scan_dict, f, indent=2)

        
        # STEP : ---------Creating a indexable list of tools inside an indexable list of servers for each mapping with issues and vulnerabilities found in the server-------------
        Console().print(f"Creating a indexable list of tools inside an indexable list of servers for each mapping with issues and vulnerabilities found in the server 🟨",style="bold yellow")
        list_of_tools_per_server = []
        error_messages = []

        if raw_scan_dict[server_config_path]["error"]:
            raise Exception(f"Error: {raw_scan_dict[server_config_path]['error']['message']} , Exception: {raw_scan_dict[server_config_path]['error']['exception']}")
        
        servers = raw_scan_dict[server_config_path]["servers"]
        Console().print(f"Number of servers found : {len(servers)} 🟩",style="bold green")
        for server in servers:
            server_tools = []
            server_name = server["name"]
            Console().print(f"Server {server_name} found , fetching tools...🟩",style="bold orange3")

            #if server encountered an error , then skip to next server after saving error message
            if error in server or server["signature"]==None:
                error_messages.append(f"Server {server_name} encountered an error : {server['error']['message']} ")
                Console().print(f"Server {server_name} encountered an error : {server['error']['message']} 🟥",style="magenta2")
                continue
            tools = server["signature"]["tools"]
            for tool in tools:
                Console().print(f"Tool {tool['name']} found , fetching description...🟩",style="bold orange3")
                tool_name = tool["name"]
                tool_description = tool["description"]
                tool_input_schema = tool["inputSchema"]
                tool = {
                    "name": tool_name,
                    "description": tool_description.encode("utf-8").decode("utf-8",errors="ignore"),
                    "input_schema": tool_input_schema,
                }
                server_tools.append(tool)
            list_of_tools_per_server.append(server_tools)

        # STEP : ------------------------------Mapping the tools with the issues and vulnerabilities found in the server----------------------------------------
        Console().print(f"Mapping the tools with the issues and vulnerabilities found in the server 🟨",style="bold yellow")
        final_issues = []
        issues = raw_scan_dict[server_config_path]["issues"]
        Console().print(f"Number of issues found : {len(issues)} 🟩",style="bold green")
        for issue in issues:
            if issue["extra_data"] == None:
                Console().print(f"Issue {issue['code']} found , mapping to tool {list_of_tools_per_server[issue['reference'][0]][issue['reference'][1]]} 🟩",style="bold green")
                
                issue_dict = {
                        "issue_code": issue["code"],
                        "issue_message": issue["message"],
                        "issue_type": "unknown",
                        "server": servers[issue["reference"][0]]["name"],
                        "tool": list_of_tools_per_server[issue["reference"][0]][issue["reference"][1]],
                        "issue_severity": "unknown"
                    }
                final_issues.append(issue_dict)
                continue
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
        Console().print(f"Number of issues found : {len(final_issues)} 🟩",style="bold green")

        # for testing
        return_result = {"final_issues": final_issues, "error_messages": error_messages}
        with open("final_issues.json", "w+") as f:
            json.dump(return_result, f, indent=2)

        Console().print(f"Finished the mcp-scan command for the server config path: {server_config_path} 🟩",style="bold green")
        return return_result
    
    except Exception as e:
        Console().print(f"Scan failed 🟥 ❌ with error: {e}",style="bold red")
        return str(e)


if __name__ == "__main__":
    results = run_mcp_scan("C:\\Users\\HP\\Desktop\\DevSecShield\\tools\\mcp_utils\\test-server-mcp.json")
    # print(results["final_issues"][-1]) if type(results) == dict else print(results)
    # print(results["error_messages"]) if type(results) == dict else None

