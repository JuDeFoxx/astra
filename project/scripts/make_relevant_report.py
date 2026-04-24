import json

data = json.load(open("cve_relevance.json", encoding="utf-8"))

relevant = [x for x in data if x.get("decision") == "likely_relevant"]

report = []
for item in relevant:
    report.append({
        "cve": item.get("cve", ""),
        "severity": item.get("severity", ""),
        "package": item.get("package", ""),
        "installed": item.get("installed", ""),
        "fixed": item.get("fixed", ""),
        "category": item.get("categories", []),
        "evidence": item.get("evidence", []),
        "decision": item.get("decision", ""),
        "title": item.get("title", ""),
    })

json.dump(report, open("relevant_report.json", "w", encoding="utf-8"), indent=2, ensure_ascii=False)

with open("relevant_report.txt", "w", encoding="utf-8") as f:
    for item in report:
        f.write("=" * 80 + "\n")
        f.write(f'CVE: {item["cve"]}\n')
        f.write(f'Severity: {item["severity"]}\n')
        f.write(f'Package: {item["package"]}\n')
        f.write(f'Installed: {item["installed"]}\n')
        f.write(f'Fixed: {item["fixed"]}\n')
        f.write(f'Category: {", ".join(item["category"])}\n')
        f.write(f'Decision: {item["decision"]}\n')
        f.write(f'Title: {item["title"]}\n')
        f.write("Evidence:\n")
        if item["evidence"]:
            for ev in item["evidence"]:
                f.write(f"  - {ev}\n")
        else:
            f.write("  - none\n")

print("DONE")
print("Relevant CVEs:", len(report))

