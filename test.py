import subprocess 
import json
def run_semgrep():
    cmd=[ "uvx" , "mcp-scan" , "C:\\Users\\HP\\Desktop\\DevSecShield\\test-server-mcp.json" , "--json" , "--opt-out" , "--storage-file" , "mcp_results","--full-toxic-flows"]
    result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # print(result.stdout.decode("utf-8"))
    # print(result.stderr.decode("utf-8"))

    if result.returncode != 0:
        print(f"Error: {result.stderr.decode('utf-8')}")
        return

    with open("mcp_results.json", "w") as f:
        json_data = json.loads(result.stdout.decode("utf-8"))
        json_formatted_str = json.dumps(json_data, indent=2)
        f.write(json_formatted_str)

if __name__ == "__main__":
    run_semgrep()

