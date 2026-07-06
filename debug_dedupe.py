import re

n1 = "John Smith"
n2 = "John D. Smith"
_PUNCT = str.maketrans("", "", ".'-")

def _norm_key(s):
    return re.sub(r"\s+", " ", s.strip().translate(_PUNCT)).lower()

k1 = _norm_key(n1)
k2 = _norm_key(n2)
print(f"Name 1: {repr(n1)}")
print(f"Key 1: {repr(k1)}")
print(f"Name 2: {repr(n2)}")
print(f"Key 2: {repr(k2)}")
print(f"Equal: {k1 == k2}")

# Also test hyphen
n3 = "Mary-Jane Watson"
n4 = "Mary Jane Watson"
k3 = _norm_key(n3)
k4 = _norm_key(n4)
print()
print(f"Name 3: {repr(n3)}")
print(f"Key 3: {repr(k3)}")
print(f"Name 4: {repr(n4)}")
print(f"Key 4: {repr(k4)}")
print(f"Equal: {k3 == k4}")
