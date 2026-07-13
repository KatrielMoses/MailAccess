"""Run the real extractors on the real rootaccess.tech/about page."""
import asyncio
import json
import sys
import os

sys.path.insert(0, os.getcwd())

with open('about_raw.html', encoding='utf-8') as f:
    html = f.read()

# === 1. extract_people on its own (is_team_page=True, aggressive=False) ===
from backend.core.structured_data_extractor import extract_people, _extract_dom_team_card_records, _extract_heading_title_records, _extract_json_ld_records, _extract_structured_blocks_records, _extract_mailto_records

PAGE_URL = "https://rootaccess.tech/about"
DOMAIN = "rootaccess.tech"

print("=" * 70)
print("METHOD 1: extract_people(html, page_url, domain, is_team_page=True, aggressive=False)")
print("=" * 70)
records = extract_people(html, PAGE_URL, DOMAIN, is_team_page=True, aggressive=False)
print(f"  Records returned: {len(records)}")
for r in records:
    print(f"  - name='{r.name}' title={r.title!r} src={r.source_type} conf={r.confidence}")

print()
print("=" * 70)
print("METHOD 1a: extract_people(html, page_url, domain, is_team_page=True, aggressive=True)")
print("=" * 70)
records_agg = extract_people(html, PAGE_URL, DOMAIN, is_team_page=True, aggressive=True)
print(f"  Records returned: {len(records_agg)}")
for r in records_agg:
    print(f"  - name='{r.name}' title={r.title!r} src={r.source_type} conf={r.confidence}")

print()
print("=" * 70)
print("Per-method debug — what does EACH individual method return?")
print("=" * 70)

print()
print("--- _extract_json_ld_records ---")
jl = _extract_json_ld_records(html, PAGE_URL, DOMAIN)
print(f"  count: {len(jl)}")
for r in jl: print(f"  {r}")

print()
print("--- _extract_structured_blocks_records (microdata/rdfa/hcard) ---")
sb = _extract_structured_blocks_records(html, PAGE_URL, DOMAIN)
print(f"  count: {len(sb)}")
for r in sb: print(f"  {r}")

print()
print("--- _extract_dom_team_card_records ---")
dtc = _extract_dom_team_card_records(html, PAGE_URL, is_team_page=True)
print(f"  count: {len(dtc)}")
for r in dtc: print(f"  {r}")

print()
print("--- _extract_heading_title_records (team pages only) ---")
ht = _extract_heading_title_records(html, PAGE_URL, DOMAIN)
print(f"  count: {len(ht)}")
for r in ht: print(f"  {r}")

print()
print("--- _extract_mailto_records ---")
mt = _extract_mailto_records(html, PAGE_URL, is_team_page=True)
print(f"  count: {len(mt)}")
for r in mt: print(f"  {r}")

print()
print("=" * 70)
print("METHOD 2: discover_company_page_names (legacy body-text path)")
print("=" * 70)
from backend.core.company_page_names import discover_company_page_names
from backend.core.http_client import build_client

async def run_legacy():
    async with build_client(timeout=5.0, follow_redirects=True) as client:
        names = await discover_company_page_names(
            "rootaccess.tech", transport=client, max_pages=5
        )
        print(f"  count: {len(names)}")
        for n in names:
            print(f"  - name='{n.name}' title={n.title_or_role!r} src_type={n.source_type} url={n.source_url}")

asyncio.run(run_legacy())
