import sys
import os

LOG_FILE = "runtime_log.txt"

def detect_category(filename: str, func_name: str):
    text = f"{filename} {func_name}".lower()

    if "auth" in text:
        return "auth"

    if "render" in func_name or "template" in text:
        return "template"

    if "csrf" in text:
        return "csrf"

    if "session" in text:
        return "session"

    if "request" in text:
        return "request"

    return None


def trace_calls(frame, event, arg):
    if event != "call":
        return trace_calls

    code = frame.f_code
    func_name = code.co_name
    filename = code.co_filename

    category = detect_category(filename, func_name)

    if category:
        line = f"[RUNTIME] category={category} func={func_name} file={filename}\n"

        print(line, end="")

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)

    return trace_calls


def start_runtime_monitor():
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

    sys.settrace(trace_calls)

    print("[RUNTIME] monitor started")
