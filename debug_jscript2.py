import sys
sys.path.insert(0, "C:/MailAccess")

from backend.core.company_page_names import _extract_json_ld_persons, _walk_json_ld

# Test 1: Direct walk
data1 = {"@type": "Person", "name": "Jane Doe", "jobTitle": "VP Engineering", "email": "jane@example.com"}
r1 = _walk_json_ld(data1)
print("Walk result 1:", r1)

# Test 2: JSON string extracted from HTML
html = '<script type="application/ld+json">{"@type":"Person","name":"Jane Doe","jobTitle":"VP Engineering","email":"jane@example.com"}</script>'
r2 = _extract_json_ld_persons(html)
print("Extract result:", r2)

# Test 3: Multi-script HTML
html2 = """<html><head>
<script type="application/ld+json">{"@type":"Person","name":"Alice Wonder","jobTitle":"CTO"}</script>
</head></html>"""
r3 = _extract_json_ld_persons(html2)
print("Extract result 2:", r3)
