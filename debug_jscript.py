import re
import json

_JSON_LD_RE = re.compile(
    r'<script[^>]*\btype\s*=\s*["\']application/ld\+json["\'][^>]*>(.*?)</script\s*>',
    flags=re.IGNORECASE | re.DOTALL,
)

html = '<script type="application/ld+json">{"@type":"Person","name":"Jane Doe","jobTitle":"VP Engineering","email":"jane@example.com"}</script>'
matches = _JSON_LD_RE.findall(html)
print("Matches:", matches)
print("HTML repr:", repr(html))
print("HTML len:", len(html))

# Try a simpler regex
_SIMPLE_RE = re.compile(r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>([^<]*)</script>', re.IGNORECASE | re.DOTALL)
matches2 = _SIMPLE_RE.findall(html)
print("Simple matches:", matches2)
