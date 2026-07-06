import sys
sys.path.insert(0, "C:/MailAccess")
import backend.core.name_quality as nq
import inspect
src = inspect.getsource(nq.name_suspicion_penalty)
print(src)
