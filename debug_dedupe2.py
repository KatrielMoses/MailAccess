import re

_PUNCT = str.maketrans("", "", "'-")  # only apostrophe and hyphen

def _norm_key(s):
    no_hyphen = s.replace("-", " ")
    return re.sub(r"\s+", " ", no_hyphen.strip().translate(_PUNCT)).lower()

n1 = "John Smith"
n2 = "John D. Smith"
n3 = "Mary-Jane Watson"
n4 = "Mary Jane Watson"
n5 = "O'Brien Kelly"
n6 = "Obrien Kelly"

print("Period kept (only '- stripped):")
print(f"  '{n1}' -> '{_norm_key(n1)}'")
print(f"  '{n2}' -> '{_norm_key(n2)}'")
print(f"  same: {_norm_key(n1) == _norm_key(n2)}")
print()
print(f"  '{n3}' -> '{_norm_key(n3)}'")
print(f"  '{n4}' -> '{_norm_key(n4)}'")
print(f"  same: {_norm_key(n3) == _norm_key(n4)}")
print()
print(f"  '{n5}' -> '{_norm_key(n5)}'")
print(f"  '{n6}' -> '{_norm_key(n6)}'")
print(f"  same: {_norm_key(n5) == _norm_key(n6)}")

# Test longer form preference
print()
print("Longer form preference:")
_PUNCT2 = str.maketrans("", "", ".-'")  # with period

def _norm_key2(s):
    no_hyphen = s.replace("-", " ")
    return re.sub(r"\s+", " ", no_hyphen.strip().translate(_PUNCT2)).lower()

n1k = _norm_key2("John Smith")
n2k = _norm_key2("John D. Smith")
print(f"  'John Smith' key='{n1k}', len={len('John Smith')}")
print(f"  'John D. Smith' key='{n2k}', len={len('John D. Smith')}")
print(f"  same key: {n1k == n2k}")
