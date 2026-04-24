import os
import re
import json

PROJECT_PATH = "./demo_project"

PATTERNS = {
    "admin": [
        r"django\.contrib\.admin",
        r"from\s+django\.contrib\s+import\s+admin",
        r"admin\.site",
    ],
    "csrf": [
        r"csrf_exempt",
        r"csrf_token",
        r"CsrfViewMiddleware",
    ],
    "xss": [
        r"mark_safe",
        r"safe\b",
        r"autoescape",
    ],
    "template": [
        r"render\(",
        r"render_to_string",
        r"TemplateResponse",
        r"templates?",
    ],
    "orm": [
        r"\.objects\.",
        r"raw\(",
        r"cursor\(",
        r"execute\(",
        r"queryset",
    ],
    "upload": [
        r"FileField",
        r"ImageField",
        r"request\.FILES",
        r"upload_to",
    ],
    "session": [
        r"request\.session",
        r"SessionMiddleware",
        r"sessionid",
    ],
    "auth": [
        r"django\.contrib\.auth",
        r"login\(",
        r"authenticate\(",
        r"permission_required",
    ],
    "redirect": [
        r"redirect\(",
        r"HttpResponseRedirect",
    ],
    "cache": [
        r"django\.core\.cache",
        r"cache\.",
    ],
}

EXCLUDE_DIRS = {"venv", "__pycache__", ".git", ".idea"}
EXCLUDE_FILES = {
    "scan_project_usage.py",
    "classify_cves.py",
    "match_cves_to_usage.py",
    "build_cve_context.py",
    "parse_trivy.py",
    "nvd_lookup.py",
    "extract_patch_from_advisory.py",
    "filter_real_vulns.py",
}

results = {k: [] for k in PATTERNS}

for root, dirs, files in os.walk(PROJECT_PATH):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

    for name in files:
        if name in EXCLUDE_FILES:
            continue

        if not (name.endswith(".py") or name.endswith(".html") or name.endswith(".txt")):
            continue

        path = os.path.join(root, name)

        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                text = f.read()

            for category, patterns in PATTERNS.items():
                for p in patterns:
                    if re.search(p, text):
                        results[category].append(path)
                        break

        except Exception:
            pass

results = {k: sorted(set(v)) for k, v in results.items()}

json.dump(results, open("project_usage.json", "w", encoding="utf-8"), indent=2, ensure_ascii=False)

print("DONE")
for k, v in results.items():
    print(f"{k}: {len(v)}")
