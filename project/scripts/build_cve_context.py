import json
import os

cves = json.load(open("cves.json", encoding="utf-8"))

cache = {}
if os.path.exists("nvd_cache.json"):
    cache = json.load(open("nvd_cache.json", encoding="utf-8"))

out = []

for item in cves:
    cve_id = item["cve"]
    desc = ""
    refs = []

    cached = cache.get(cve_id)
    if cached:
        refs = cached.get("refs", [])

    desc = item.get("title") or ""

    out.append({
        "cve": cve_id,
        "package": item.get("package", ""),
        "installed": item.get("installed", ""),
        "fixed": item.get("fixed", ""),
        "severity": item.get("severity", ""),
        "title": item.get("title", ""),
        "description": desc,
        "refs": refs,
    })

json.dump(out, open("cve_context.json", "w", encoding="utf-8"), indent=2, ensure_ascii=False)

print("DONE")
print("Saved:", len(out))
