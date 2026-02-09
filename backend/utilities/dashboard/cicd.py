import datetime

def get_cicd_vuln_chart_data(results_list : list[tuple[list[dict],datetime.date]]) -> dict:
    """
    Get the vulnerability chart data for the given results list.
    Args:
        results_list : list[tuple[list[dict],datetime.date]]
    Returns:
        dict
    Example:
    {
        "2026-02-07": {
            "Critical": 10,
            "High": 20,
            "Medium": 30,
            "Low": 40,
        } , 
        "2026-02-08": {
            "Critical": 10,
            "High": 20,
            "Medium": 30,
            "Low": 40,
        } , 
        and so on 
    }
    """
    vulns_over_time_chart_data = {}
    for result, created_at in results_list:
        date_key = created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at)
        if date_key not in vulns_over_time_chart_data:
            vulns_over_time_chart_data[date_key] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for finding in result:
            for vuln in finding.get("vulnerabilities", []):
                impact = (vuln.get("impact") or "").strip()
                if impact == "Critical":
                    vulns_over_time_chart_data[date_key]["Critical"] += 1
                elif impact == "High":
                    vulns_over_time_chart_data[date_key]["High"] += 1
                elif impact == "Medium":
                    vulns_over_time_chart_data[date_key]["Medium"] += 1
                elif impact == "Low":
                    vulns_over_time_chart_data[date_key]["Low"] += 1
    return vulns_over_time_chart_data

    # mock_data = {
    #     "2026-02-07": {
    #         "Critical": 10,
    #         "High": 60,
    #         "Medium": 0,
    #         "Low": 0,
    #     } , 
    #     "2026-02-08": {
    #         "Critical": 10,
    #         "High": 20,
    #         "Medium": 20,
    #         "Low": 0,
    #     } , 
    #     "2026-02-09": {
    #         "Critical": 10,
    #         "High": 20,
    #         "Medium": 0,
    #         "Low": 40,
    #     } , 
    #     "2026-02-10": {
    #         "Critical": 0,
    #         "High": 20,
    #         "Medium": 30,
    #         "Low": 40,
    #     } , 
    #     "2026-02-11": {
    #         "Critical": 10,
    #         "High": 20,
    #         "Medium": 30,
    #         "Low": 40,
    #     } , 
    #     "2026-02-12": {
    #         "Critical": 100,
    #         "High": 20,
    #         "Medium": 30,
    #         "Low": 40,
    #     } , 
    #     "2026-02-13": {
    #         "Critical": 10,
    #         "High": 20,
    #         "Medium": 30,
    #         "Low": 40,
    #     } , 
    # }
    # return mock_data