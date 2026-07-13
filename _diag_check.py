import asyncio
from backend.core.stealth_client import StealthSession, TIMING_PROFILES
from backend.core.email_extraction import extract_emails
from backend.core.cf_decode import cf_decode
import re

async def check():
    session = StealthSession(timing_profile=TIMING_PROFILES['t2'])
    resp = await session.get('https://rootaccess.tech/about')
    html = cf_decode(resp.text)

    raw = re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', html)
    print('Raw regex finds:', raw)

    found = extract_emails(html, 'rootaccess.tech')
    print('extract_emails finds:', [e.email for e in found])

    mailtos = re.findall(r'mailto:([^\s"\'<>]+)', html)
    print('mailto links:', mailtos)

    cf = re.findall(r'data-cfemail="([^"]+)"', html)
    print('data-cfemail:', cf)

asyncio.run(check())
