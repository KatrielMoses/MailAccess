"""Trace what _HeadingAndTitleParser actually captures for each h2/h3."""
import sys, os
sys.path.insert(0, os.getcwd())

with open('about_raw.html', encoding='utf-8') as f:
    html = f.read()

from backend.core.structured_data_extractor import _HeadingAndTitleParser, _TITLE_TOKEN_RE, _looks_like_person_heading

parser = _HeadingAndTitleParser()
parser.feed(html)
parser.close()
parser.finalize()

print("All headings (tag, name, next_text) from _HeadingAndTitleParser:")
print("=" * 70)
for h in parser.headings:
    tag = h.get("tag")
    name = h.get("name")
    nxt = h.get("next_text")
    is_person = _looks_like_person_heading(name)
    title_match = bool(_TITLE_TOKEN_RE.search(nxt)) if nxt else False
    print(f"  <{tag}> {name!r}")
    print(f"     next_text={nxt!r}")
    print(f"     is_person_heading={is_person}  title_token_in_next={title_match}")
    print()
