"""Inspect the rootaccess.tech/about page structure."""
from collections import Counter
import re

with open('about_raw.html', encoding='utf-8') as f:
    html = f.read()

# Find all repeated structural blocks
class_counts = Counter()
for tag in re.finditer(r'<([a-zA-Z][a-zA-Z0-9]*)\b[^>]*\bclass="([^"]+)"', html):
    classes = tag.group(2).split()
    for cls in classes:
        class_counts[cls] += 1

# Show classes appearing 2+ times (likely card containers)
print('Repeated classes (count >= 2):')
for cls, count in sorted(class_counts.items(), key=lambda x: -x[1]):
    if count >= 2:
        print(f'  {cls}: {count}')

# Show all h2/h3/h4 text
print()
print('Headings (h2/h3/h4):')
for m in re.finditer(r'<(h[234])\b[^>]*>(.*?)</\1>', html, flags=re.IGNORECASE | re.DOTALL):
    tag = m.group(1).lower()
    inner = re.sub(r'<[^>]+>', ' ', m.group(2))
    inner = re.sub(r'\s+', ' ', inner).strip()
    print(f'  <{tag}>: {inner[:100]}')

# Check for structured data: JSON-LD, microdata, hcard
print()
print('=== Structured data presence ===')
json_ld_count = len(re.findall(r'<script[^>]*type=["\']application/ld\+json["\']', html, re.IGNORECASE))
print(f'  JSON-LD scripts: {json_ld_count}')

# microdata itemtype=Person
microdata_person = len(re.findall(r'itemtype=["\'][^"\']*Person', html, re.IGNORECASE))
print(f'  microdata Person: {microdata_person}')

# vcard class
vcard_count = len(re.findall(r'class="[^"]*\bvcard\b', html, re.IGNORECASE))
print(f'  vcard class: {vcard_count}')

# mailto links
mailto_count = len(re.findall(r'href=["\']mailto:', html, re.IGNORECASE))
print(f'  mailto links: {mailto_count}')

# imgs
img_count = len(re.findall(r'<img\b', html, re.IGNORECASE))
print(f'  imgs: {img_count}')

# Find any structural container that repeats
# Look for the team cards structure - try finding parent divs containing "Katriel" and "Aaron"
print()
print('=== Searching for Katriel / Aaron in HTML ===')
for needle in ['Katriel', 'Aaron', 'Joseph', 'Delzyn', 'Moses']:
    count = html.count(needle)
    print(f'  {needle}: {count} occurrences')
    if count > 0:
        # Find first context
        idx = html.find(needle)
        snippet = html[max(0, idx-200):idx+300]
        # Strip tags for readability
        clean = re.sub(r'<[^>]+>', ' ', snippet)
        clean = re.sub(r'\s+', ' ', clean).strip()
        print(f'    Context: ...{clean[:400]}...')
