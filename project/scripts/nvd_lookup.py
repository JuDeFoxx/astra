import json
import requests
import time
import os

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

API_KEY = os.getenv("NVD_API_KEY")

HEADERS = {}
if API_KEY:
    HEADERS["apiKey"] = API_KEY

cves = json.load(open("cves.json", encoding="utf-8"))

if os.path.exists("nvd_cache.json"):
    cache = json.load(open("nvd_cache.json", encoding="utf-8"))
else:
    cache = {}

results = []

for item in cves[:10]:   
    cve_id = item["cve"]

    print("Checking:", cve_id)

    if cve_id in cache:
        print("  from cache")
        results.append(cache[cve_id])
        continue

    try:
        r = requests.get(
            BASE_URL,
            headers=HEADERS,
            params={"cveId": cve_id},
            timeout=10
        )

        if r.status_code != 200:
            print("  error:", r.status_code)
            time.sleep(6)
            continue

        data = r.json()
        references = []

        vulns = data.get("vulnerabilities", [])
        if vulns:
            refs = vulns[0]["cve"].get("references", [])
            for ref in refs:
                url = ref.get("url", "")
                tags = ref.get("tags", [])

                if (
                    "github" in url.lower()
                    or "patch" in url.lower()
                    or "Vendor Advisory" in tags
                ):
                    references.append(url)

        result = {
            "cve": cve_id,
            "refs": references
        }

        cache[cve_id] = result
        results.append(result)

        time.sleep(6)

    except Exception as e:
        print("  exception:", e)
        time.sleep(6)

json.dump(cache, open("nvd_cache.json", "w", encoding="utf-8"), indent=2)
json.dump(results, open("patch_links.json", "w", encoding="utf-8"), indent=2)

print("DONE")
