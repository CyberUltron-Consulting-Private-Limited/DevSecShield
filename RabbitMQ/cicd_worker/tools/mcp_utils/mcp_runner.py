import subprocess 
import json
import tempfile
import shutil
from rich.progress import Progress,Task
from rich.console import Console
def run_mcp_scan(server_config_json:str) -> list[dict] | str:

    try:
        Console().print(f"Validating the server config json 🟨",style="bold yellow")
        data_json = json.loads(server_config_json)
        Console().print(f"JSON Valid and creating json file 🟩",style="bold green")
        server_config_json_temp = tempfile.NamedTemporaryFile(delete=False, suffix=".json",mode="w+")
        json.dump(data_json, server_config_json_temp, indent=2)
        server_config_json_temp.flush()
        server_config_path = server_config_json_temp.name
        Console().print(f"Server config json validated and created a temporary file successfully 🟩",style="bold green")

        # STEP : ------------------------------------------------------------Running the mcp-scan command----------------------------------------------------------
        Console().print(f"Starting the mcp-scan command for the server config path: {server_config_path} 🟨",style="bold yellow")
        temp_dir = tempfile.mkdtemp()
        cmd=[ "uvx" , "mcp-scan" ,server_config_path, "--json" , "--opt-out" , "--full-toxic-flows","--storage-file", temp_dir ]
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        shutil.rmtree(temp_dir)
        server_config_json_temp.close()

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
        with open("mcp_test_raw.json", "w+") as f:
            json.dump(raw_scan_dict, f, indent=2)

        
        # STEP : ---------Creating a indexable list of tools inside an indexable list of servers for each mapping with issues and vulnerabilities found in the server-------------
        Console().print(f"Creating a indexable list of tools inside an indexable list of servers for each mapping with issues and vulnerabilities found in the server 🟨",style="bold yellow")
        list_of_tools_per_server = []
        error_messages = []

        # Log top-level errors but continue processing (e.g., analysis API errors shouldn't stop server processing)
        if raw_scan_dict[server_config_path].get("error"):
            top_level_error = raw_scan_dict[server_config_path]["error"]
            error_msg = f"Top-level scan error (non-fatal): {top_level_error.get('message', 'Unknown error')} - {top_level_error.get('category', 'unknown')}"
            error_messages.append(error_msg)
            Console().print(f"{error_msg} 🟨",style="bold yellow")
        
        servers = raw_scan_dict[server_config_path]["servers"]
        Console().print(f"Number of servers found : {len(servers)} 🟩",style="bold green")
        for server in servers:
            server_tools = []
            server_name = server["name"]
            Console().print(f"Server {server_name} found , fetching tools...🟩",style="bold orange3")

            #if server encountered an error , then skip to next server after saving error message
            # Skip server if it has an error or no signature (failed servers)
            if (("error" in server and server["error"] is not None) or server.get("signature") is None):
                error_msg = server.get("error", {}).get("message", "Unknown error") if server.get("error") else "No signature available"
                error_messages.append(f"Server {server_name} encountered an error : {error_msg}")
                Console().print(f"Server {server_name} encountered an error : {error_msg} 🟥",style="magenta2")
                list_of_tools_per_server.append([])  # Add empty list to maintain index alignment
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
        
        Console().print(f"List of tools per server: {list_of_tools_per_server} 🟩",style="bold green")

        # STEP : ------------------------------Mapping the tools with the issues and vulnerabilities found in the server----------------------------------------
        Console().print(f"Mapping the tools with the issues and vulnerabilities found in the server 🟨",style="bold yellow")
        final_issues = []
        issues = raw_scan_dict[server_config_path]["issues"]
        Console().print(f"Number of issues found : {len(issues)} 🟩",style="bold green")
        for issue in issues:
            if issue["extra_data"] == None:
                Console().print(f"Issue reference 0: {issue['reference'][0]} 1: {issue['reference'][1]} 🟩",style="bold green")
                
                server_idx = issue['reference'][0]
                tool_idx = issue['reference'][1]
                
                # Handle cases where reference[1] is None (server-level issue, not tool-level)
                if tool_idx is None:
                    tool_info = None
                else:
                    server_tools = list_of_tools_per_server[server_idx] if server_idx < len(list_of_tools_per_server) else []
                    tool_info = server_tools[tool_idx] if tool_idx < len(server_tools) else None
                
                Console().print(f"Issue {issue['code']} found , mapping to tool {tool_info} 🟩",style="bold green")
                
                issue_dict = {
                        "issue_code": issue["code"],
                        "issue_message": issue["message"],
                        "issue_type": "unknown",
                        "server": servers[server_idx]["name"] if server_idx < len(servers) else "unknown",
                        "tool": tool_info,
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
                    server_idx = item["reference"][0]
                    tool_idx = item["reference"][1]
                    
                    # Handle cases where tool_idx is None or out of range
                    if tool_idx is None:
                        tool_info = None
                    else:
                        server_tools = list_of_tools_per_server[server_idx] if server_idx < len(list_of_tools_per_server) else []
                        tool_info = server_tools[tool_idx] if tool_idx < len(server_tools) else None
                    
                    issue_dict = {
                        "issue_code": issue_code,
                        "issue_message": issue_message,
                        "issue_type": issue_type,
                        "server": servers[server_idx]["name"] if server_idx < len(servers) else "unknown",
                        "tool": tool_info,
                        "issue_severity": issue_severity
                    }
                    final_issues.append(issue_dict)
        Console().print(f"Number of issues found : {len(final_issues)} 🟩",style="bold green")

        # for testing
        return_result = {"final_issues": final_issues, "error_messages": error_messages}
        # with open("mcp_test.json", "w+") as f:
        #     json.dump(return_result, f, indent=2)

        Console().print(f"Finished the mcp-scan command for the server config path: {server_config_path} 🟩",style="bold green")
        return return_result
    
    except Exception as e:
        Console().print(f"Scan failed 🟥 ❌ with error: {e}",style="bold red")
        raise e


if __name__ == "__main__":
    json_data = json.load(open("C:\\Users\\HP\\Desktop\\DevSecShield\\rabbitmq\\worker\\tools\\mcp_utils\\remote_mcp.json"))
    # json_data = json.load(open("C:\\Users\\HP\\Desktop\\DevSecShield\\rabbitmq\\worker\\tools\\mcp_utils\\test-server-mcp.json"))
    string_json = str(json_data)
    string_json = string_json.replace("'", '"')
    Console().print(f"String json: {string_json} 🟩",style="bold green")
    results = run_mcp_scan(string_json)
    with open("mcp_test_results.json", "w+") as f:
        json.dump(results, f, indent=2)
    # print(results["final_issues"][-1]) if type(results) == dict else print(results)
    # print(results["error_messages"]) if type(results) == dict else None

