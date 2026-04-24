import json

data = json.load(open("cve_context.json", encoding="utf-8"))

RULES = {
    "admin": ["admin", "django admin", "contrib.admin"],
    "csrf": ["csrf", "cross-site request forgery"],
    "xss": ["xss", "cross site scripting", "cross-site scripting"],
    "template": ["template", "templates", "render"],
    "orm": ["sql", "queryset", "orm", "query", "injection"],
    "upload": ["upload", "filefield", "imagefield", "file"],
    "session": ["session", "cookie"],
    "auth": ["auth", "authentication", "login", "permission"],
    "redirect": ["redirect", "url validation"],
    "cache": ["cache", "caching"],
}

def classify(text: str):
    t = (text or "").lower()
    found = []

    for category, words in RULES.items():
        for w in words:
            if w in t:
                found.append(category)
                break

    if not found:
        found.append("other")

    return found

out = []

for item in data:
    text = (item.get("title", "") + " " + item.get("description", "")).strip()
    cats = classify(text)

    row = dict(item)
    row["categories"] = cats
    out.append(row)

json.dump(out, open("cve_classified.json", "w", encoding="utf-8"), indent=2, ensure_ascii=False)

print("DONE")
print("Saved:", len(out))

stats = {}
for item in out:
    for cat in item["categories"]:
        stats[cat] = stats.get(cat, 0) + 1

print("Category stats:")
for k, v in sorted(stats.items(), key=lambda x: (-x[1], x[0])):
    print(k, v)
