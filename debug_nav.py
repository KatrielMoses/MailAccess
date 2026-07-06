import sys
sys.path.insert(0, "C:/MailAccess")

import importlib.util

spec = importlib.util.spec_from_file_location(
    "nq", "C:/MailAccess/backend/core/name_quality.py"
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

nav = mod._NAVIGATION_TOKENS
print("cloud in nav:", "cloud" in nav)
print("engineer in nav:", "engineer" in nav)
print("john in nav:", "john" in nav)
print("devops in nav:", "devops" in nav)

# Also check role words
role = mod._ROLE_WORDS
print("john in role:", "john" in role)

# Check is_plausible for John Cloud Engineer
print("is_plausible:", mod.is_plausible_person_name("John Cloud Engineer"))
