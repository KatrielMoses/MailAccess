import sys
sys.path.insert(0, '.')
from backend.core.structured_data_extractor import _HeadingAndTitleParser
with open('about_raw.html', encoding='utf-8') as f:
    html = f.read()

parser = _HeadingAndTitleParser()
parser.feed(html)
parser.close()
parser.finalize()

with open('parsed_headings.txt', 'w', encoding='utf-8') as out:
    for idx, h in enumerate(parser.headings):
        out.write(f"{idx}: <{h.get('tag')}> '{h.get('name')}' -> '{h.get('next_text')}'\n")
