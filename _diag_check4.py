import asyncio
from backend.core.stealth_client import StealthSession, TIMING_PROFILES
from backend.core.cf_decode import cf_decode
import re, json

async def check():
    session = StealthSession(timing_profile=TIMING_PROFILES['t2'])
    resp = await session.get('https://rootaccess.tech/about')
    html = cf_decode(resp.text)

    # Find __next_f chunks
    pattern = r'self\.__next_f\.push\(\[(\d+),"(.*?)"\]\)'
    chunks = re.findall(pattern, html, re.DOTALL)
    full = ''
    for idx, data in sorted(chunks, key=lambda x: int(x[0])):
        full += data

    emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', full)
    print('Emails in RSC stream:', emails)
    print('RSC stream length:', len(full))

    if 'mail' in full.lower():
        idx = full.lower().find('mail')
        print('Around mail:', repr(full[max(0,idx-100):idx+200]))
    if 'contact' in full.lower():
        idx = full.lower().find('contact')
        print('Around contact:', repr(full[max(0,idx-100):idx+200]))

asyncio.run(check())
