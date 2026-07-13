"""Show the HTML around each person h2 to see why one gets a title and the other doesn't."""
import re

with open('about_raw.html', encoding='utf-8') as f:
    html = f.read()

# Find each h2 with its surrounding 1500 chars
for needle in ['Aaron Joseph Jean', 'Katriel Delzyn Moses', 'Meet the Founders']:
    print("=" * 70)
    print(f"Context around: {needle!r}")
    print("=" * 70)
    idx = html.find(needle)
    if idx == -1:
        print("  not found")
        continue
    start = max(0, idx - 300)
    end = min(len(html), idx + 2500)
    snippet = html[start:end]
    # Pretty-print: insert newlines before block tags for readability
    pretty = re.sub(r'<(h[1-6]|p|div|/p|/div|section|/section|article|/article)\b', r'\n<\1', snippet)
    print(pretty[:3500])
    print()
