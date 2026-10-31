"""Fetch CVE records from the NVD API 2.0 (rate-limited) and keep description, CVSS, CWE and CPE ranges."""
import json, sys, time, urllib.request, urllib.error

IDS = sys.argv[1].split(",")
PATH = __import__("os").path.join(__import__("os").path.dirname(__import__("os").path.abspath(__file__)), "sources", "nvd_cves.json")
out = {}
try:
    out = json.load(open(PATH))
except Exception:
    pass
for cve in IDS:
    if cve in out and "--refetch" not in sys.argv:
        continue
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    for attempt in range(4):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "zs-kb-builder"}), timeout=40) as r:
                data = json.load(r)
            break
        except urllib.error.HTTPError as e:
            time.sleep(10 * (attempt + 1)); data = None
        except Exception as e:
            time.sleep(10 * (attempt + 1)); data = None
    if not data or not data.get("vulnerabilities"):
        out[cve] = {"error": "not found"}
    else:
        v = data["vulnerabilities"][0]["cve"]
        desc = next((d["value"] for d in v.get("descriptions", []) if d["lang"] == "en"), "")
        metrics = v.get("metrics", {})
        cvss = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                m = metrics[key][0]["cvssData"]
                cvss = {"version": m.get("version"), "score": m.get("baseScore"), "vector": m.get("vectorString"),
                        "severity": metrics[key][0].get("baseSeverity") or m.get("baseSeverity")}
                break
        cwes = sorted({d["value"] for w in v.get("weaknesses", []) for d in w.get("description", [])})
        cpes = []
        for conf in v.get("configurations", []):
            for node in conf.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if m.get("vulnerable"):
                        cpes.append({k: m.get(k) for k in ("criteria", "versionStartIncluding", "versionStartExcluding",
                                                            "versionEndIncluding", "versionEndExcluding") if m.get(k)})
        out[cve] = {"published": v.get("published", "")[:10], "description": desc, "cvss": cvss, "cwe": cwes,
                    "cpes": cpes, "source": f"https://nvd.nist.gov/vuln/detail/{cve}"}
    json.dump(out, open(PATH, "w"), indent=1)
    print(cve, (out[cve].get("cvss") or {}).get("score"), out[cve].get("description", out[cve].get("error"))[:90], flush=True)
    time.sleep(6.5)
