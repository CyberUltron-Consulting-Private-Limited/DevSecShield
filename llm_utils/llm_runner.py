import os
import subprocess
import json
from pathlib import Path
import tempfile
from typing import Optional, Dict, Any, List, Literal
import uuid
from dotenv import load_dotenv


def run_garak_scan(
    model_type: Literal["openai", "anthropic", "gemini","custom"],
    model_name: str,
    probes: Literal["all", "ansiescape", "atkgen", "audio", "av_spam_scanning", "continuation", "dan", "divergence", "doctor", "donotanswer", "encoding", "exploitation", "fileformats", "glitch", "goodside", "grandma", "latentinjection", "leakreplay", "lmrc", "malwaregen", "misleading", "packagehallucination", "phrasing", "promptinject", "realtoxicityprompts", "sata", "snowball", "suffix", "tap", "test", "topic", "visual_jailbreak", "xss"] = "all",
    api_key: Optional[str] = None,
    headers: Optional[dict] = None,
    request_template: Optional[dict] = None,
    response_json_field: Optional[str] = None,
    generations: Optional[int] = 1,
    method: Literal["get", "post"] = "post",
    model_uri: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run a Garak scan and return important metrics.
    
    Supports multiple probes by passing comma-separated probe names (e.g., "dan.Ablation_Dan_11_0,dan.DanInTheWild").
    When multiple probes are used, each probe gets its own separate vulnerability summary entry for granular analysis.

    Args:
        model_type: e.g. "openai", "anthropic", "gemini", "custom"
        model_name: e.g. "gpt-4", "claude-3-opus", "llama2:latest"
        probes: probe set, default "all". Can be comma-separated for multiple probes
        api_key: provider API key (if needed)

    Returns:
        Dictionary with summarized scan results and metrics, including separate vulnerability entries for each probe
    """
    

    

    # -------------------------STEP [1] : Retrive Config Template (in both dict and json string) -----------------------------------------------------------------------
    config_path = Path(os.path.realpath(__file__)).parent / "rest_configs" / f"{model_type}.json"

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)
    json_string = json.dumps(config)
    
    # -------------------------STEP [2] : Update Config Template -----------------------------------------------------------------------
    """
    This step updates the config template for both custom and non-custom models.
    the "config" variable is the final dictionary that contains the config template for both custom and non-custom models.
    """
    if model_type == "custom":
        new_config = config.copy()
        new_config["rest"]["RestGenerator"]["method"] = method
        new_config["rest"]["RestGenerator"]["headers"] = headers
        new_config["rest"]["RestGenerator"]["req_template_json_object"] = request_template
        new_config["rest"]["RestGenerator"]["response_json_field"] = response_json_field
        new_config["rest"]["RestGenerator"]["uri"] = model_uri
        new_json_string = json.dumps(new_config)
    else:
        new_json_string = json_string.replace("<API_KEY>", api_key)
        new_json_string = new_json_string.replace("<MODEL_NAME>", model_name)

    print(new_json_string)
    config = json.loads(new_json_string)

    # -------------------------STEP [3] : Construct a job_id and results directory-----------------------------------------------------------------------
    job_id = str(uuid.uuid4())
    results_dir = Path(os.path.realpath(__file__)).parent / "results"
    results_dir.mkdir(exist_ok=True)
    report_prefix = results_dir / f"garak_{job_id}"

    # -------------------------STEP [4] : Create a new temporary config file with the updated values-----------------------------------------------------------------------
    """
    This step writes the updated config for both custom and non-custom models into a temporary config file.
    which will be used by Garak to run the scan.
    """
    
    temp_json = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    #create a new temporary config file with the updated values
    with open(temp_json.name, "w+", encoding="utf-8") as f:
        json.dump(config, f)

    

    # -------------------------STEP [5] : Build Command seperately for custom and non-custom models-----------------------------------------------------------------------

    cmd = [
        "python",
        "-m",
        "garak",
        "--model_type", "rest", "-G"
        ,temp_json.name,
        "--probes", probes,
        "--report_prefix", str(report_prefix)
    ]

    
    # because --model_type is being deprecated in garak ( un tested and doesn't work )
    # cmd = [
    #     "python",
    #     "-m",
    #     "garak",
    #     "--target_type", "rest", "-G"
    #     ,temp_json.name,
    #     "--probes", probes,
    #     "--report_prefix", str(report_prefix)
    # ]

    if generations:
        cmd.extend([
            "--generations", str(generations)])

    # -------------------------STEP [6] : Run Garak-----------------------------------------------------------------------
    print("⭐ GARAK CMD ==> ",cmd)
    subprocess.run(cmd, check=True)

    # -------------------------STEP [7] : Delete the temporary config file-----------------------------------------------------------------------
    temp_json.close()

    # -------------------------STEP [8] : Locate results files (supporting multiple naming conventions)-----------------------------------------------------------------------
    jsonl_candidates = [
        f"{report_prefix}.report.jsonl",
        f"{report_prefix}.jsonl",
    ]
    html_candidates = [
        f"{report_prefix}.report.html",
        f"{report_prefix}.html",
    ]
    hitlog_candidates = [
        f"{report_prefix}.hitlog.jsonl",
        f"{report_prefix}.hitlog",
    ]

    def first_existing(paths: List[str]) -> str:
        for p in paths:
            if Path(p).exists():
                return p
        return paths[0]

    jsonl_file = first_existing(jsonl_candidates)
    html_file = first_existing(html_candidates)
    hitlog_file = first_existing(hitlog_candidates)

    # -------------------------STEP [9] : Parse results JSONL if available-----------------------------------------------------------------------
    total_tests = 0
    total_hits = 0
    probes_used = set()
    risk_level = "unknown"
    probes_summary = {}

    if Path(jsonl_file).exists():
        with open(jsonl_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Look for eval entries with probe results
                if entry.get("entry_type") == "eval":
                    probe_name = entry.get("probe")
                    detector_name = entry.get("detector")
                    passed = entry.get("passed", 0)
                    total = entry.get("total", 0)
                    
                    if probe_name and total > 0:
                        total_tests += total
                        hits = total - passed
                        total_hits += hits
                        probes_used.add(probe_name)
                        
                        # Flat summary keyed by detector+probe for traceability
                        probe_key = f"{detector_name}_{probe_name}"
                        probe_bucket = {
                            "probe": probe_name,
                            "detector": detector_name,
                            "passed": passed,
                            "total": total,
                            "hit_rate": round((hits / total) * 100, 2)
                        }
                        probes_summary[probe_key]=probe_bucket


                # Look for digest entries with overall risk assessment
                elif entry.get("entry_type") == "digest":
                    eval_data = entry.get("eval", {})
                    for group_name, group_data in eval_data.items():
                        if isinstance(group_data, dict) and "_summary" in group_data:
                            summary_data = group_data["_summary"]
                            group_score = summary_data.get("score", 0)
                            group_defcon = summary_data.get("group_defcon", 5)
                            
                            # Determine risk level based on DEFCON level
                            if group_defcon <= 2:
                                risk_level = "critical"
                            elif group_defcon == 3:
                                risk_level = "high"
                            elif group_defcon == 4:
                                risk_level = "medium"
                            else:
                                risk_level = "low"

    # -------------------------STEP [10] : Finalize per-probe hit rates-----------------------------------------------------------------------
    for probe_name, probe_bucket in probes_summary.items():
        p_total = probe_bucket["total"]
        p_passed = probe_bucket["passed"]
        p_hits = max(p_total - p_passed, 0)
        probe_bucket["hit_rate"] = round((p_hits / p_total) * 100, 2) if p_total > 0 else 0.0

    # -------------------------STEP [11] : Compute hit rate-----------------------------------------------------------------------
    hit_rate = (total_hits / total_tests * 100) if total_tests > 0 else 0.0

    # -------------------------STEP [12] : Build simplified summary dict with only key metrics-----------------------------------------------------------------------
    summary = {
        "status": "completed" if total_tests > 0 else "no results",
        "model_name": model_name,
        "total_tests": total_tests,
        "total_hits": total_hits,
        "hit_rate_percent": round(hit_rate, 2),
        "risk_level": risk_level,
        "probes_used": sorted(list(probes_used)),
        "probes_summary": probes_summary,
    }
    
    try:
        print("🟨 Cleaning up report files after the scan is complete")
        #removing report files after the scan is complete
        os.remove(jsonl_file)
        print("🟨 JSONL file removed")
        os.remove(html_file)
        print("🟨 HTML file removed")
        os.remove(hitlog_file)
        print("🟨 Hitlog file removed")
    except Exception as e:
        print(f"🟥 Error removing report files: {str(e)}")

    return summary


if __name__=="__main__":
    load_dotenv()
    
    # Test with multiple probes to demonstrate separate vulnerability summaries
    print("Testing Garak scan with multiple probes...")
    print("Probes: dan.Ablation_Dan_11_0,dan.DanInTheWild")
    print("Each probe will now get its own separate vulnerability summary entry\n")
    
    results = run_garak_scan(
        model_type="custom",
        model_name="gpt-4o",
        headers={
                "Authorization": "Bearer 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",
                "Content-Type": "application/json"
                },
        request_template={
            "model": "gpt-4o",
            "input": "$INPUT"
          },
        response_json_field="$.output[0].content[0].text",
        probes="malwaregen.TopLevel",
        model_uri="https://api.openai.com/v1/responses",
    )

    # results = run_garak_scan(
    #     model_type="openai",
    #     model_name="gpt-4o",
    #     probes="malwaregen.TopLevel",
    #     api_key=os.getenv("OPENAI_API_KEY"),
    # )
    print(json.dumps(results, indent=2))
