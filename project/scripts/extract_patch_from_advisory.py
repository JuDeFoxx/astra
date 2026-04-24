import json
import requests
import re
import time
from urllib.parse import urljoin

data = json.load(open("patch_links.json", encoding="utf-8"))

def extract_links(html, base_url):
    hrefs = re.findall(r'href=["\']([^"\']+)["\']', html, flags=re.I)
    res = []
    for h in hrefs:
        if h.startswith("#"):
            continue
        res.append(urljoin(base_url, h))
    return res

def is_patch_link(u: str):
    u2 = u.lower()
    if "github.com" in u2 and ("/commit/" in u2 or "/pull/" in u2):
        return True
    if u2.endswith(".patch") or u2.endswith(".diff"):
        return True
    if "patch" in u2 and "github.com" in u2:
        return True
    return False

out = []

for item in data:
    cve = item["cve"]
    refs = item.get("refs", [])

    patch_candidates = set()

    for ref in refs:
        try:
            r = requests.get(ref, timeout=15)
            if r.status_code != 200:
                continue
            links = extract_links(r.text, ref)
            for l in links:
                if is_patch_link(l):
                    patch_candidates.add(l)
            time.sleep(1)
        except Exception:
            pass

    out.append({
        "cve": cve,
        "patch_links": sorted(patch_candidates)
    })

json.dump(out, open("patch_candidates.json", "w", encoding="utf-8"), indent=2, ensure_ascii=False)

print("DONE")
print("With patch links:", sum(1 for x in out if x["patch_links"]))
