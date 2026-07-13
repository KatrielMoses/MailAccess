import asyncio
from backend.core.stealth_client import StealthSession, TIMING_PROFILES
from backend.core.cf_decode import cf_decode
import re, json

async def check():
    session = StealthSession(timing_profile=TIMING_PROFILES['t2'])
    resp = await session.get('https://rootaccess.tech/about')
    html = cf_decode(resp.text)

    # Extract __NEXT_DATA__
    m = re.search(r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>', html)
    if m:
        data = json.loads(m.group(1))
        print('NEXT_DATA props keys:', list(data.get('props', {}).get('pageProps', {}).keys()))
        pp = data['props']['pageProps']
        text = json.dumps(pp)
        emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', text)
        print('Emails in NEXT_DATA pageProps:', emails)
        for k, v in pp.items():
            vstr = json.dumps(v)
            if 'mail' in vstr.lower() or '@' in vstr:
                print(f'Key with email refs: {k}')
                print(vstr[:500])
    else:
        print('No __NEXT_DATA__ found')

asyncio.run(check())
