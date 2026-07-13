import asyncio
from backend.core.stealth_client import StealthSession, TIMING_PROFILES
from backend.core.cf_decode import cf_decode
import re

async def check():
    session = StealthSession(timing_profile=TIMING_PROFILES['t2'])
    resp = await session.get('https://rootaccess.tech/about')
    html = cf_decode(resp.text)

    # Print 500 chars around any 'mail' or 'contact' or 'href' or '@' occurrence
    for match in re.finditer(r'(mail|contact|href|@)', html, re.IGNORECASE):
        start = max(0, match.start() - 100)
        end = min(len(html), match.end() + 100)
        print('---')
        print(html[start:end])

asyncio.run(check())
