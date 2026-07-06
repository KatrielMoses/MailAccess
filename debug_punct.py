import inspect
import backend.core.name_quality as nq

src = inspect.getsource(nq.dedupe_names)
print("_NORM_PUNCT in source:", "_NORM_PUNCT" in src)
print("Period in source:", "period" in src.lower())

# Find the maketrans line
import re
m = re.search(r'_NORM_PUNCT\s*=.*?str\.maketrans.*?\n', src)
if m:
    print("Found:", m.group())
else:
    print("Not found - checking for _PUNCT")
    m2 = re.search(r'_PUNCT\s*=.*?str\.maketrans.*?\n', src)
    if m2:
        print("Found old:", m2.group())
