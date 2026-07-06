import sys
sys.path.insert(0, "C:/MailAccess")

import importlib.util

# Load directly from .py source, bypassing any cached .pyc
spec = importlib.util.spec_from_file_location(
    "nq", "C:/MailAccess/backend/core/name_quality.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

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
    plausible = mod.is_plausible_person_name(name)
    penalty = mod.name_suspicion_penalty(name)
    print(f"{name}: plausible={plausible}, penalty={penalty}")
