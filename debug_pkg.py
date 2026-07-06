import sys
sys.path.insert(0, "C:/MailAccess")

# Import through normal package chain (same as pytest)
import backend.core.name_quality as nq

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
    plausible = nq.is_plausible_person_name(name)
    penalty = nq.name_suspicion_penalty(name)
    print(f"{name}: plausible={plausible}, penalty={penalty}")

# Also check what the nav tokens check does
tokens = ["John", "Cloud", "Engineer"]
for t in tokens:
    tl = t.lower().strip(".,;:'-")
    print(f"  Token '{t}' -> '{tl}' -> in nav: {tl in nq._NAVIGATION_TOKENS}")
