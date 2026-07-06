import sys
sys.path.insert(0, "C:/MailAccess")

from backend.core.company_page_names import discover_for_tests, _extract_json_ld_persons, _extract_names_from_text

html = '<html><head><script type="application/ld+json">{"@type":"Person","name":"Jane Doe","jobTitle":"VP Engineering","email":"jane@example.com"}</script></head><body>x</body></html>'

print("HTML repr:", repr(html))
print()

# Step 1: Extract JSON-LD directly
persons = _extract_json_ld_persons(html)
print("JSON-LD persons:", persons)
print()

# Step 2: Check what _extract_names_from_text returns
from backend.core.company_page_names import _html_to_text
text = _html_to_text(html)
print("Text from HTML:", repr(text[:200]))

names = _extract_names_from_text(text, domain="x.com", page_furniture=(None, None))
print("Names from text:", names)
print()

# Step 3: Full discover_for_tests
result = discover_for_tests({'https://x.com/about': html}, 'x.com')
print("discover_for_tests result:", result)
print("Count:", len(result))
for r in result:
    print(f"  - {r.name}, type={r.source_type}, conf={r.confidence}, email={r.email}")
