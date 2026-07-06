import sys
sys.path.insert(0, "C:/MailAccess")

import importlib.util, importlib

# Load module directly from .py file, bypassing cache
spec = importlib.util.spec_from_file_location(
    "name_quality_fresh",
    "C:/MailAccess/backend/core/name_quality.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

from name_quality_fresh import is_plausible_person_name, name_suspicion_penalty

cases = [
    "John Cloud Engineer",
    "Kubernetes Cluster",
    "Jane Doe",
    "Azure Smith",
    "DevOps Engineer",
    "Cloud Platform",
    "Branch Network",
]

for name in cases:
    plausible = is_plausible_person_name(name)
    penalty = name_suspicion_penalty(name)
    print(f"{name}: plausible={plausible}, penalty={penalty}")
