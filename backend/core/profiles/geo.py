"""Location normalisation for profile fields: city, region and country code only.

``normalize_location("Indore, India")`` → ``{"city": "Indore", "country_code": "IN"}``.
Accepts ISO codes ("IN"), country names, Chess.com country URLs
(``https://api.chess.com/pub/country/IN``) and "City, Region, Country" strings. Anything
that looks like a street address or a phone number is refused (``None``): we keep city,
region and country, never more.
"""

from __future__ import annotations

import re

# ISO 3166-1 alpha-2 → English short name; aliases follow after "|".
_TABLE = """
AF:Afghanistan|AX:Aland Islands|AL:Albania|DZ:Algeria|AS:American Samoa|AD:Andorra|AO:Angola|
AI:Anguilla|AQ:Antarctica|AG:Antigua and Barbuda|AR:Argentina|AM:Armenia|AW:Aruba|AU:Australia|
AT:Austria|AZ:Azerbaijan|BS:Bahamas|BH:Bahrain|BD:Bangladesh|BB:Barbados|BY:Belarus|BE:Belgium|
BZ:Belize|BJ:Benin|BM:Bermuda|BT:Bhutan|BO:Bolivia|BA:Bosnia and Herzegovina|BW:Botswana|
BR:Brazil|BN:Brunei|BG:Bulgaria|BF:Burkina Faso|BI:Burundi|CV:Cape Verde|KH:Cambodia|
CM:Cameroon|CA:Canada|KY:Cayman Islands|CF:Central African Republic|TD:Chad|CL:Chile|CN:China|
CO:Colombia|KM:Comoros|CG:Congo|CD:Democratic Republic of the Congo|CR:Costa Rica|
CI:Cote d'Ivoire|HR:Croatia|CU:Cuba|CW:Curacao|CY:Cyprus|CZ:Czechia|DK:Denmark|DJ:Djibouti|
DM:Dominica|DO:Dominican Republic|EC:Ecuador|EG:Egypt|SV:El Salvador|GQ:Equatorial Guinea|
ER:Eritrea|EE:Estonia|SZ:Eswatini|ET:Ethiopia|FK:Falkland Islands|FO:Faroe Islands|FJ:Fiji|
FI:Finland|FR:France|GF:French Guiana|PF:French Polynesia|GA:Gabon|GM:Gambia|GE:Georgia|
DE:Germany|GH:Ghana|GI:Gibraltar|GR:Greece|GL:Greenland|GD:Grenada|GP:Guadeloupe|GU:Guam|
GT:Guatemala|GG:Guernsey|GN:Guinea|GW:Guinea-Bissau|GY:Guyana|HT:Haiti|HN:Honduras|
HK:Hong Kong|HU:Hungary|IS:Iceland|IN:India|ID:Indonesia|IR:Iran|IQ:Iraq|IE:Ireland|
IM:Isle of Man|IL:Israel|IT:Italy|JM:Jamaica|JP:Japan|JE:Jersey|JO:Jordan|KZ:Kazakhstan|
KE:Kenya|KI:Kiribati|KP:North Korea|KR:South Korea|KW:Kuwait|KG:Kyrgyzstan|LA:Laos|LV:Latvia|
LB:Lebanon|LS:Lesotho|LR:Liberia|LY:Libya|LI:Liechtenstein|LT:Lithuania|LU:Luxembourg|MO:Macao|
MG:Madagascar|MW:Malawi|MY:Malaysia|MV:Maldives|ML:Mali|MT:Malta|MH:Marshall Islands|
MQ:Martinique|MR:Mauritania|MU:Mauritius|YT:Mayotte|MX:Mexico|FM:Micronesia|MD:Moldova|
MC:Monaco|MN:Mongolia|ME:Montenegro|MS:Montserrat|MA:Morocco|MZ:Mozambique|MM:Myanmar|
NA:Namibia|NR:Nauru|NP:Nepal|NL:Netherlands|NC:New Caledonia|NZ:New Zealand|NI:Nicaragua|
NE:Niger|NG:Nigeria|MK:North Macedonia|NO:Norway|OM:Oman|PK:Pakistan|PW:Palau|PS:Palestine|
PA:Panama|PG:Papua New Guinea|PY:Paraguay|PE:Peru|PH:Philippines|PL:Poland|PT:Portugal|
PR:Puerto Rico|QA:Qatar|RE:Reunion|RO:Romania|RU:Russia|RW:Rwanda|KN:Saint Kitts and Nevis|
LC:Saint Lucia|VC:Saint Vincent and the Grenadines|WS:Samoa|SM:San Marino|
ST:Sao Tome and Principe|SA:Saudi Arabia|SN:Senegal|RS:Serbia|SC:Seychelles|SL:Sierra Leone|
SG:Singapore|SX:Sint Maarten|SK:Slovakia|SI:Slovenia|SB:Solomon Islands|SO:Somalia|
ZA:South Africa|SS:South Sudan|ES:Spain|LK:Sri Lanka|SD:Sudan|SR:Suriname|SE:Sweden|
CH:Switzerland|SY:Syria|TW:Taiwan|TJ:Tajikistan|TZ:Tanzania|TH:Thailand|TL:Timor-Leste|TG:Togo|
TO:Tonga|TT:Trinidad and Tobago|TN:Tunisia|TR:Turkey|TM:Turkmenistan|TC:Turks and Caicos Islands|
TV:Tuvalu|UG:Uganda|UA:Ukraine|AE:United Arab Emirates|GB:United Kingdom|US:United States|
UY:Uruguay|UZ:Uzbekistan|VU:Vanuatu|VA:Vatican City|VE:Venezuela|VN:Vietnam|
VG:British Virgin Islands|VI:US Virgin Islands|EH:Western Sahara|YE:Yemen|ZM:Zambia|ZW:Zimbabwe
"""
_ALIASES = {
    "usa": "US", "u.s.a.": "US", "u.s.": "US", "united states of america": "US", "america": "US",
    "uk": "GB", "u.k.": "GB", "great britain": "GB", "britain": "GB", "england": "GB",
    "scotland": "GB", "wales": "GB", "northern ireland": "GB", "republic of ireland": "IE",
    "russian federation": "RU", "korea": "KR", "republic of korea": "KR", "czech republic": "CZ",
    "uae": "AE", "holland": "NL", "the netherlands": "NL", "viet nam": "VN", "turkiye": "TR",
    "türkiye": "TR", "ivory coast": "CI", "côte d'ivoire": "CI", "macedonia": "MK",
    "swaziland": "SZ", "burma": "MM", "bharat": "IN", "deutschland": "DE", "espana": "ES",
    "españa": "ES", "brasil": "BR", "méxico": "MX", "italia": "IT", "nippon": "JP",
}

_NAME_TO_CODE: dict[str, str] = {}
CODE_TO_NAME: dict[str, str] = {}
for _item in _TABLE.replace("\n", "").split("|"):
    if ":" in _item:
        _code, _name = _item.split(":", 1)
        CODE_TO_NAME[_code] = _name
        _NAME_TO_CODE[_name.lower()] = _code
_NAME_TO_CODE.update(_ALIASES)

_STREET = re.compile(
    r"\b\d+[a-z]?\s+(?:[a-z.'-]+\s+){0,3}(?:street|st|road|rd|avenue|ave|lane|ln|drive|dr|"
    r"boulevard|blvd|nagar|marg|cross|main|sector|block|floor|flat|apt|suite)\b",
    re.I,
)
_LONG_DIGITS = re.compile(r"(?:\d[\s().+-]*){6,}")


def looks_private(text: str) -> bool:
    """A street address, a postcode-style number run or a phone number."""
    return bool(_STREET.search(text) or _LONG_DIGITS.search(text))


def country_code(value: str) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    m = re.search(r"/country/([A-Za-z]{2})/?$", text)  # Chess.com country URL
    if m:
        text = m.group(1)
    if len(text) == 2 and text.isalpha() and text.upper() in CODE_TO_NAME:
        return text.upper()
    return _NAME_TO_CODE.get(text.lower().strip(" ."))


def normalize_location(raw: str | None) -> dict[str, str] | None:
    """``{city?, region?, country_code?}`` from a free-text location, or None."""
    text = re.sub(r"\s+", " ", str(raw or "")).strip(" ,")
    if not text or len(text) > 120 or looks_private(text):
        return None
    whole = country_code(text)  # "IN", "India", a Chess.com country URL
    if whole:
        return {"country_code": whole}
    m = re.fullmatch(r"(.+?)\s*\(([A-Za-z]{2})\)", text)  # "Ireland (IE)"
    if m and country_code(m.group(2)):
        rest = normalize_location(m.group(1)) or {}
        return {**{k: v for k, v in rest.items() if k != "country_code"},
                "country_code": m.group(2).upper()}
    parts = [p.strip() for p in re.split(r"[,·|]", text) if p.strip()]
    if not parts:
        return None
    out: dict[str, str] = {}
    code = country_code(parts[-1])
    if code:
        out["country_code"] = code
        parts = parts[:-1]
    elif len(parts) == 1 and country_code(parts[0]) is None:
        # A single token that isn't a country: treat it as a city.
        return {"city": parts[0]} if parts[0].isascii() or len(parts[0]) < 40 else None
    if parts:
        out["city"] = parts[0]
    if len(parts) >= 2:
        out["region"] = parts[1]
    return out or None
