from runtime_monitor import start_runtime_monitor

start_runtime_monitor()

from demo_project.views import my_view

print("[TEST] calling my_view")

my_view(None)

print("[TEST] done")
