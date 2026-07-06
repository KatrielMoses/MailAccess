import sys
sys.path.insert(0, "C:/MailAccess")
import backend.core.name_quality as nq

# Check what's in the function source
import inspect
src = inspect.getsource(nq.name_suspicion_penalty)
print("=== name_suspicion_penalty source ===")
print(src[:500])
print()
print("=== nav tokens check ===")
print([t for t in ["cloud", "engineer", "john"] if t in nq._NAVIGATION_TOKENS])
print("Penalty:", nq.name_suspicion_penalty("John Cloud Engineer"))
