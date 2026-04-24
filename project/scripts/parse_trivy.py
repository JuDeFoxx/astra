import json

REPORT = "report.json"

data = json.load(open(REPORT, encoding="utf-8"))

items = []
seen = set()

results = data.get("Results", [])
for r in results:
    vulns = r.get("Vulnerabilities") or []
    for v in vulns:
        cve = v.get("VulnerabilityID") or ""
        pkg = v.get("PkgName") or ""
        installed = v.get("InstalledVersion") or ""
        fixed = v.get("FixedVersion") or ""
        severity = v.get("Severity") or ""
        title = v.get("Title") or ""

        key = (cve, pkg, installed)
        if cve and key not in seen:
            seen.add(key)
            items.append({
                "cve": cve,
                "package": pkg,
                "installed": installed,
                "fixed": fixed,
                "severity": severity,
                "title": title,
            })

# сортировка: сначала по severity, потом по CVE
sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
items.sort(key=lambda x: (sev_rank.get(x["severity"], 9), x["cve"]))

json.dump(items, open("cves.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)

with open("cves.txt", "w", encoding="utf-8") as f:
    for x in items:
        f.write(f'{x["severity"]:9} {x["cve"]}  {x["package"]}=={x["installed"]}  fixed:{x["fixed"]}\n')

print("OK")
print("Found:", len(items))
print("Top 10:")
for x in items[:10]:
    print(x["severity"], x["cve"], x["package"], x["installed"])
