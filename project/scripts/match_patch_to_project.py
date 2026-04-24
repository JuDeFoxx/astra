import json
import os

patch_data = json.load(open("patch_analysis.json", encoding="utf-8"))

PROJECT_PATH = "./demo_project"

def project_contains_path_fragment(fragment: str):
    for root, dirs, files in os.walk(PROJECT_PATH):
        for f in files:
            path = os.path.join(root, f)
            if fragment in path:
                return True
    return False

out = []

for item in patch_data:
    cve = item["cve"]
    matches = []

    for patch in item.get("patch_analysis", []):
        for f in patch.get("changed_files", []):
            if project_contains_path_fragment(f):
                matches.append(f)

    result = dict(item)
    result["patch_matches_project"] = bool(matches)
    result["matched_files"] = matches

    if not matches:
        result["final_decision"] = "likely_not_exploitable"
    else:
        result["final_decision"] = "possibly_exploitable"

    out.append(result)

json.dump(out, open("final_analysis.json", "w", encoding="utf-8"), indent=2, ensure_ascii=False)

print("DONE")
print("Possibly exploitable:", sum(1 for x in out if x["final_decision"] == "possibly_exploitable"))
print("Not exploitable:", sum(1 for x in out if x["final_decision"] == "likely_not_exploitable"))

