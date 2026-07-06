import sys
sys.path.insert(0, "C:/MailAccess")

# Force fresh import
import importlib
import backend.core.name_quality
importlib.reload(backend.core.name_quality)

from backend.core.name_quality import is_plausible_person_name, name_suspicion_penalty

cases = [
    "John Cloud Engineer",
    "Kubernetes Cluster",
    "Jane Doe",
    "Azure Smith",
    "DevOps Engineer",
]

for name in cases:
    plausible = is_plausible_person_name(name)
    penalty = name_suspicion_penalty(name)
    print(f"{name}: plausible={plausible}, penalty={penalty}")
