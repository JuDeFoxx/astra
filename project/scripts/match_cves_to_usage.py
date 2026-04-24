import json

cves = json.load(open("cve_classified.json", encoding="utf-8"))
usage = json.load(open("project_usage.json", encoding="utf-8"))

out = []

for item in cves:
    cats = item.get("categories", [])
    evidence = []

    for cat in cats:
        files = usage.get(cat, [])
        if files:
            evidence.extend(files[:5])

    used = len(evidence) > 0

    result = dict(item)
    result["used_in_project"] = used
    result["evidence"] = sorted(set(evidence))
    result["decision"] = "likely_relevant" if used else "likely_not_relevant"

    out.append(result)

json.dump(out, open("cve_relevance.json", "w", encoding="utf-8"), indent=2, ensure_ascii=False)

print("DONE")
print("Likely relevant:", sum(1 for x in out if x["used_in_project"]))
print("Likely not relevant:", sum(1 for x in out if not x["used_in_project"]))
