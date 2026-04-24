import json
from packaging import version

cves = json.load(open("cves.json", encoding="utf-8"))

real = []

for item in cves:
    installed = item["installed"]
    fixed_versions = item["fixed"]

    if not fixed_versions:
        continue

    fixed_list = [v.strip() for v in fixed_versions.split(",")]

    try:
        installed_v = version.parse(installed)

        for f in fixed_list:
            fixed_v = version.parse(f)

            if installed_v < fixed_v:
                real.append(item)
                break

    except Exception:
        continue

json.dump(real, open("real_vulns.json", "w", encoding="utf-8"), indent=2)

print("Total:", len(cves))
print("Real exploitable:", len(real))
