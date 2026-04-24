import json

# читаем финальный анализ
data = json.load(open("final_analysis.json", encoding="utf-8"))

# читаем runtime лог
with open("runtime_log.txt", encoding="utf-8") as f:
    runtime_lines = f.readlines()

runtime_categories = set()

for line in runtime_lines:
    if "category=" in line:
        cat = line.split("category=")[1].split()[0]
        runtime_categories.add(cat)

out = []

for item in data:
    cats = item.get("categories", [])

    runtime_hit = any(c in runtime_categories for c in cats)

    result = dict(item)
    result["runtime_confirmed"] = runtime_hit

    if runtime_hit:
        result["confidence"] = "high"
    else:
        result["confidence"] = "low"

    out.append(result)

json.dump(out, open("final_with_runtime.json", "w", encoding="utf-8"), indent=2, ensure_ascii=False)

print("DONE")
print("Runtime categories:", runtime_categories)
print("High confidence:", sum(1 for x in out if x["confidence"] == "high"))
print("Low confidence:", sum(1 for x in out if x["confidence"] == "low"))
