import json
import requests
import re
from urllib.parse import urlparse

all_data = json.load(open("cve_relevance.json", encoding="utf-8"))

relevant = [x for x in all_data if x.get("decision") == "likely_relevant"]
patch_data = json.load(open("patch_candidates.json", encoding="utf-8"))

patch_map = {x["cve"]: x.get("patch_links", []) for x in patch_data}

def to_patch_url(url: str):
    u = url.strip()

    if u.endswith(".patch") or u.endswith(".diff"):
        return u

    if "github.com" in u and "/commit/" in u:
        return u + ".patch"

    return None

def extract_changed_files_and_funcs(text: str):
    files = []
    funcs = []

    for line in text.splitlines():
        if line.startswith("diff --git"):
            m = re.search(r" b/(.+)$", line)
            if m:
                files.append(m.group(1))

        if line.startswith("@@"):
            funcs.append(line.strip())

    return sorted(set(files)), funcs[:20]

out = []

for item in relevant:
    cve = item["cve"]
    links = patch_map.get(cve, [])
    analyzed = []

    for link in links:
        patch_url = to_patch_url(link)
        if not patch_url:
            continue

        try:
            r = requests.get(patch_url, timeout=20)
            if r.status_code != 200:
                continue

            files, funcs = extract_changed_files_and_funcs(r.text)

            analyzed.append({
                "source_link": link,
                "patch_url": patch_url,
                "changed_files": files,
                "changed_hunks": funcs,
            })

        except Exception as e:
            analyzed.append({
                "source_link": link,
                "patch_url": patch_url,
                "error": str(e),
            })

    out.append({
        "cve": cve,
        "severity": item.get("severity", ""),
        "package": item.get("package", ""),
        "categories": item.get("categories", []),
        "decision": item.get("decision", ""),
        "evidence": item.get("evidence", []),
        "patch_analysis": analyzed,
    })

json.dump(out, open("patch_analysis.json", "w", encoding="utf-8"), indent=2, ensure_ascii=False)

print("DONE")
print("Analyzed CVEs:", len(out))
print("With patch analysis:", sum(1 for x in out if x["patch_analysis"]))
