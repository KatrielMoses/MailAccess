"""Per-platform profile parsers (UC3), keyed by corpus site id.

Each parser reads the response the existence probe already received (``ctx.json`` /
``ctx.body``); a few make one follow-up request to the platform's official public API
when the probe response carries too little (GitLab user detail, PyPI package JSON,
GitHub API when a token is configured). Public, logged-out data only.
"""

from __future__ import annotations

import html as html_lib
import json
import re
from typing import Any, Awaitable, Callable

from .fields import Profile
from .generic import meta_tags, parse_html


class Ctx:
    def __init__(self, *, site_id: str, username: str, url: str, probe_url: str,
                 body: str, client: Any, profile: Profile) -> None:
        self.site_id = site_id
        self.username = username
        self.url = url  # human profile URL (field source for page data)
        self.probe_url = probe_url  # what the probe fetched (field source for API data)
        self.body = body or ""
        self.client = client
        self.p = profile
        try:
            self.json: Any = json.loads(self.body) if self.body.lstrip()[:1] in ("{", "[") else None
        except ValueError:
            self.json = None

    async def fetch(self, url: str, **kwargs: Any) -> tuple[int, str]:
        from ..probe_detector import _USER_AGENT

        headers = {"User-Agent": _USER_AGENT, "Accept-Language": "en-US,en;q=0.8",
                   **kwargs.pop("headers", {})}
        try:
            resp = await self.client.request(kwargs.pop("method", "GET"), url, headers=headers,
                                             timeout=6.0, follow_redirects=True, **kwargs)
            return resp.status_code, resp.text
        except Exception:  # noqa: BLE001 - a failed follow-up just means fewer fields
            return 0, ""

    async def fetch_json(self, url: str, **kwargs: Any) -> Any:
        status, text = await self.fetch(url, **kwargs)
        if status != 200:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return None


Parser = Callable[[Ctx], Awaitable[None]]
PARSERS: dict[str, Parser] = {}


def parser(*site_ids: str) -> Callable[[Parser], Parser]:
    def wrap(fn: Parser) -> Parser:
        for sid in site_ids:
            PARSERS[sid] = fn
        return fn
    return wrap


def _get(data: Any, path: str) -> Any:
    for part in path.split("."):
        if isinstance(data, dict):
            data = data.get(part)
        elif isinstance(data, list) and part.isdigit() and int(part) < len(data):
            data = data[int(part)]
        else:
            return None
    return data


def _join(*parts: Any) -> str | None:
    text = ", ".join(str(x).strip() for x in parts if x and str(x).strip())
    return text or None


# ── official JSON APIs the probe already called ─────────────────────────────

@parser("dailymotion")
async def _dailymotion(c: Ctx) -> None:
    j, src, p = c.json or {}, c.probe_url, c.p
    p.set("name", j.get("screenname"), src)
    p.set("username", j.get("username"), src)
    p.set("avatar", j.get("avatar_720_url"), src)
    p.set("banner", j.get("cover_250_url"), src)
    p.set("bio", j.get("description"), src)
    p.set("location", j.get("country"), src)
    p.set("joined", j.get("created_time"), src)
    p.set("followers", j.get("followers_total"), src)
    p.set("following", j.get("following_total"), src)
    p.set("posts", j.get("videos_total"), src)
    p.set("verified", j.get("verified"), src)


@parser("codeforces_com")
async def _codeforces(c: Ctx) -> None:
    u, src, p = _get(c.json, "result.0") or {}, c.probe_url, c.p
    p.set("name", " ".join(x for x in (u.get("firstName"), u.get("lastName")) if x), src)
    p.set("username", u.get("handle"), src)
    p.set("avatar", u.get("titlePhoto") or u.get("avatar"), src)
    p.set("location", _join(u.get("city"), u.get("country")), src)
    p.set("joined", u.get("registrationTimeSeconds"), src)
    p.set("last_active", u.get("lastOnlineTimeSeconds"), src)
    p.set("followers", u.get("friendOfCount"), src)
    p.set("bio", u.get("organization"), src)


@parser("freelancer_com")
async def _freelancer(c: Ctx) -> None:
    users = _get(c.json, "result.users") or {}
    u = next(iter(users.values()), {}) if isinstance(users, dict) else {}
    src, p = c.probe_url, c.p
    p.set("name", u.get("public_name") or u.get("display_name"), src)
    p.set("username", u.get("username"), src)
    loc = u.get("location") or {}
    p.set("location", _join(loc.get("city"), _get(loc, "country.name")), src)
    p.set("joined", u.get("registration_date"), src)
    p.set("avatar", u.get("avatar_cdn") or u.get("avatar"), src)
    p.set("bio", u.get("tagline") or u.get("profile_description"), src)


@parser("bandlab")
async def _bandlab(c: Ctx) -> None:
    j, src, p = c.json or {}, c.probe_url, c.p
    p.set("name", j.get("name"), src)
    p.set("username", j.get("username"), src)
    if not _get(j, "picture.isDefault"):
        p.set("avatar", _get(j, "picture.url"), src)
    if not _get(j, "backgroundPicture.isDefault"):
        p.set("banner", _get(j, "backgroundPicture.url"), src)
    p.set("bio", j.get("about"), src)
    place = j.get("place")
    p.set("location", place.get("name") if isinstance(place, dict) else place, src)
    p.set("joined", j.get("createdOn"), src)
    p.set("followers", _get(j, "counters.followers"), src)
    p.set("following", _get(j, "counters.following"), src)
    p.set("verified", j.get("isVerified"), src)


@parser("picsart")
async def _picsart(c: Ctx) -> None:
    j, src, p = c.json or {}, c.probe_url, c.p
    p.set("name", j.get("name"), src)
    p.set("username", j.get("username"), src)
    if not j.get("default_profile_pic"):
        p.set("avatar", j.get("photo"), src)
    p.set("banner", j.get("cover"), src)
    p.set("bio", j.get("status_message"), src)
    p.set("followers", j.get("followers_count"), src)
    p.set("following", j.get("following_count"), src)
    p.set("posts", j.get("photos_count"), src)
    p.set("verified", j.get("is_verified"), src)


@parser("pinterest_2")
async def _pinterest(c: Ctx) -> None:
    u, src, p = _get(c.json, "data.user") or {}, c.probe_url, c.p
    p.set("name", u.get("full_name"), src)
    m = re.search(r"pinterest\.[a-z.]+/([^/]+)/?", str(u.get("profile_url") or ""))
    p.set("username", m.group(1) if m else None, src)
    avatar = str(u.get("image_small_url") or "")
    p.set("avatar", avatar.replace("/60x60_RS/", "/280x280_RS/"), src)
    p.set("bio", u.get("about"), src)
    p.set("followers", u.get("follower_count"), src)
    p.set("posts", u.get("pin_count"), src)


@parser("leetcode")
async def _leetcode(c: Ctx) -> None:
    u, src, p = _get(c.json, "data.matchedUser") or {}, c.probe_url, c.p
    prof = u.get("profile") or {}
    p.set("name", prof.get("realName"), src)
    p.set("username", u.get("username"), src)
    p.set("avatar", prof.get("userAvatar"), src)
    p.set("location", prof.get("countryName"), src)
    p.set("bio", prof.get("aboutMe"), src)
    p.add_links([*(prof.get("websites") or []), u.get("githubUrl"), u.get("twitterUrl"),
                 u.get("linkedinUrl")], src)


@parser("chess")
async def _chess(c: Ctx) -> None:
    j, src, p = c.json or {}, c.probe_url, c.p
    p.set("name", j.get("name"), src)
    p.set("username", j.get("username"), src)
    p.set("avatar", j.get("avatar"), src)
    from .geo import CODE_TO_NAME, country_code

    code = country_code(str(j.get("country") or ""))  # .../pub/country/IN
    p.set("location", _join(j.get("location"), CODE_TO_NAME.get(code or "")), src)
    p.set("joined", j.get("joined"), src)
    p.set("last_active", j.get("last_online"), src)
    p.set("followers", j.get("followers"), src)
    p.set("verified", j.get("verified"), src)
    p.add_links([j.get("twitch_url")], src)


@parser("docker_hub")
async def _docker_hub(c: Ctx) -> None:
    j, src, p = c.json or {}, c.probe_url, c.p
    p.set("name", j.get("full_name"), src)
    p.set("username", j.get("username"), src)
    p.set("avatar", j.get("gravatar_url"), src)
    p.set("location", j.get("location"), src)
    p.set("bio", j.get("company"), src)
    p.set("joined", j.get("date_joined"), src)
    p.add_links([j.get("profile_url")], src)


@parser("duolingo_2")
async def _duolingo(c: Ctx) -> None:
    u, src, p = _get(c.json, "users.0") or {}, c.probe_url, c.p
    p.set("name", u.get("name"), src)
    p.set("username", u.get("username"), src)
    picture = str(u.get("picture") or "")
    p.set("avatar", (picture + "/xlarge") if picture and "default" not in picture else None, src)
    p.set("bio", u.get("bio"), src)
    p.set("location", u.get("profileCountry"), src)
    p.set("joined", u.get("creationDate"), src)


@parser("hackerrank_2")
async def _hackerrank(c: Ctx) -> None:
    m, src, p = _get(c.json, "model") or {}, c.probe_url, c.p
    p.set("name", m.get("name") or _join(m.get("personal_first_name"), m.get("personal_last_name")), src)
    p.set("username", m.get("username"), src)
    if m.get("has_avatar_url"):
        p.set("avatar", m.get("avatar"), src)
    p.set("location", m.get("country"), src)
    p.set("joined", m.get("created_at"), src)
    p.set("bio", m.get("short_bio") or m.get("jobs_headline") or m.get("job_title"), src)
    p.set("followers", m.get("followers_count"), src)
    p.set("following", m.get("followees_count") or m.get("following_count"), src)
    p.add_links([m.get("website"), m.get("linkedin_url"), m.get("github_url")], src)


@parser("minecraft")
async def _minecraft(c: Ctx) -> None:
    c.p.set("username", (c.json or {}).get("name"), c.probe_url)


@parser("gitlab")
async def _gitlab(c: Ctx) -> None:
    u, src, p = _get(c.json, "0") or {}, c.probe_url, c.p
    p.set("name", u.get("name"), src)
    p.set("username", u.get("username"), src)
    p.set("avatar", u.get("avatar_url"), src)
    # /api/v4/users/:id now needs a token; the public profile page has the rest.
    page_url = str(u.get("web_url") or f"https://gitlab.com/{c.username}")
    status, page = await c.fetch(page_url)
    if status != 200:
        return
    page = html_lib.unescape(page)
    m = re.search(r"Member since ([A-Z][a-z]+ \d{1,2}, \d{4})", page)
    p.set("joined", m.group(1) if m else None, page_url)
    m = re.search(r'data-testid="location-icon".*?<span[^>]*>\s*([^<]+?)\s*</span>', page, re.S)
    p.set("location", m.group(1) if m else None, page_url)
    contact = page.split(">Contact</h2>", 1)[1][:6000] if ">Contact</h2>" in page else ""
    p.add_links([h for h in re.findall(r'href="(https?://[^"]+)"', contact)
                 if "gitlab.com" not in h], page_url)
    meta = meta_tags(page)
    desc = meta.get("og:description") or ""
    if desc and "GitLab" not in desc:
        p.set("bio", desc, page_url)


@parser("reddit")
async def _reddit(c: Ctx) -> None:
    d, src, p = _get(c.json, "data") or {}, c.probe_url, c.p
    sub = d.get("subreddit") or {}
    p.set("name", sub.get("title"), src)
    p.set("username", d.get("name"), src)
    p.set("avatar", html_lib.unescape(str(d.get("icon_img") or "")).split("?")[0], src)
    p.set("banner", html_lib.unescape(str(sub.get("banner_img") or "")).split("?")[0], src)
    p.set("bio", sub.get("public_description"), src)
    p.set("joined", d.get("created_utc"), src)
    p.set("posts", d.get("total_karma"), src)
    p.set("followers", sub.get("subscribers"), src)
    p.set("verified", d.get("verified"), src)


@parser("keybase")
async def _keybase(c: Ctx) -> None:
    them, src, p = _get(c.json, "them.0") or {}, c.probe_url, c.p
    prof = them.get("profile") or {}
    p.set("name", prof.get("full_name"), src)
    p.set("username", _get(them, "basics.username"), src)
    p.set("avatar", _get(them, "pictures.primary.url"), src)
    p.set("bio", prof.get("bio"), src)
    p.set("location", prof.get("location"), src)
    p.set("joined", _get(them, "basics.ctime"), src)
    proofs = _get(them, "proofs_summary.all") or []
    p.add_links([pr.get("service_url") for pr in proofs if isinstance(pr, dict)], src)


# ── PyPI (XML-RPC probe) ────────────────────────────────────────────────────

@parser("pypi")
async def _pypi(c: Ctx) -> None:
    pkgs = re.findall(r"<value><string>(?:Owner|Maintainer)</string></value>\s*"
                      r"<value><string>([^<]+)</string></value>", c.body)
    pkgs = list(dict.fromkeys(pkgs))
    p = c.p
    p.set("username", c.username, c.url)
    p.set("posts", len(pkgs), c.probe_url)
    p.add_links([f"https://pypi.org/project/{name}/" for name in pkgs[:10]], c.probe_url)
    if pkgs:
        pkg_url = f"https://pypi.org/pypi/{pkgs[0]}/json"
        info = (await c.fetch_json(pkg_url) or {}).get("info") or {}
        # Only the author name: project_urls describe the package, not the person.
        p.set("name", info.get("author") or info.get("maintainer"), pkg_url)


# ── GitHub: official API with a token; the public profile page otherwise ────

@parser("github_username")
async def _github(c: Ctx) -> None:
    from ...config import settings

    p = c.p
    token = getattr(settings, "github_token", None)
    if token:
        api = f"https://api.github.com/users/{c.username}"
        j = await c.fetch_json(api, headers={"Authorization": f"Bearer {token}",
                                             "Accept": "application/vnd.github+json"})
        if j:
            p.set("name", j.get("name"), api)
            p.set("username", j.get("login"), api)
            p.set("avatar", j.get("avatar_url"), api)
            p.set("bio", j.get("bio"), api)
            p.set("location", j.get("location"), api)
            p.set("joined", j.get("created_at"), api)
            p.set("followers", j.get("followers"), api)
            p.set("following", j.get("following"), api)
            p.set("posts", j.get("public_repos"), api)
            p.add_links([j.get("blog"), j.get("twitter_username") and
                         f"https://x.com/{j['twitter_username']}"], api)
            return
    b, src = c.body, c.url
    m = re.search(r'itemprop="name">\s*([^<]+?)\s*<', b)
    p.set("name", m.group(1) if m else None, src)
    m = re.search(r'itemprop="additionalName">\s*([^<]+?)\s*<', b)
    p.set("username", m.group(1) if m else None, src)
    m = re.search(r'data-bio-text="([^"]*)"', b)
    p.set("bio", html_lib.unescape(m.group(1)) if m else meta_tags(b).get("description"), src)
    m = re.search(r'itemprop="homeLocation"[^>]*>.*?<span[^>]*>\s*([^<]+?)\s*</span>', b, re.S)
    p.set("location", html_lib.unescape(m.group(1)) if m else None, src)
    for field, word in (("followers", "followers"), ("following", "following")):
        m = re.search(r'<span class="text-bold[^"]*">([\d.,kKmM]+)</span>\s*' + word, b)
        p.set(field, m.group(1) if m else None, src)
    m = re.search(r'data-tab-item="repositories".*?<span[^>]*title="([\d,]+)"[^>]*class="Counter', b, re.S)
    p.set("posts", m.group(1) if m else None, src)
    p.set("avatar", meta_tags(b).get("og:image"), src)
    links = re.findall(r'<li itemprop="(?:url|social)"[^>]*>.*?href="([^"]+)"', b, re.S)
    p.add_links([html_lib.unescape(u) for u in links], src)


# ── public pages: og tags / embedded app data ──────────────────────────────

@parser("instagram_2")
async def _instagram(c: Ctx) -> None:
    meta, src, p = meta_tags(c.body), c.url, c.p
    title = meta.get("og:title", "")
    m = re.match(r"(.*?)\s*\(@([^)]+)\)", title)
    if m:
        p.set("name", m.group(1), src)
        p.set("username", m.group(2), src)
    desc = meta.get("og:description", "")
    for field, word in (("followers", "Followers"), ("following", "Following"), ("posts", "Posts")):
        m = re.search(r"([\d.,]+[KkMm]?)\s+" + word, desc)
        p.set(field, m.group(1) if m else None, src)
    m = re.search(r'on Instagram: "(.*)"\s*$', desc, re.S)
    p.set("bio", m.group(1) if m else None, src)
    p.set("avatar", meta.get("og:image"), src)


@parser("facebook_2")
async def _facebook(c: Ctx) -> None:
    meta, src, p = meta_tags(c.body), c.url, c.p
    p.set("name", meta.get("og:title"), src)
    m = re.search(r"facebook\.com/([^/?#]+)/?", meta.get("og:url", ""))
    if m and m.group(1) not in ("profile.php", "people"):
        p.set("username", m.group(1), src)
    m = re.search(r"([\d.,]+[KkMm]?)\s+followers", meta.get("og:description", ""), re.I)
    p.set("followers", m.group(1) if m else None, src)
    p.set("avatar", meta.get("og:image"), src)


@parser("hackerearth_2")
async def _hackerearth(c: Ctx) -> None:
    meta, src, p = meta_tags(c.body), c.url, c.p
    m = re.match(r"(.*?)\s*\|\s*Developer Profile", meta.get("og:title", ""))
    if m and m.group(1) != c.username:
        p.set("name", m.group(1), src)
    p.set("username", c.username, src)


@parser("snapchat_2")
async def _snapchat(c: Ctx) -> None:
    m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', c.body, re.S)
    src, p = c.url, c.p
    try:
        props = json.loads(m.group(1))["props"]["pageProps"] if m else {}
    except (ValueError, KeyError):
        props = {}
    profile = props.get("userProfile") or {}
    info = profile.get("userInfo") or profile.get("publicProfileInfo") or {}
    p.set("name", info.get("displayName") or info.get("title"), src)
    p.set("username", info.get("username"), src)
    p.set("avatar", _get(info, "bitmoji3d.avatarImage.url") or info.get("profilePictureUrl")
          or info.get("snapcodeImageUrl"), src)
    p.set("banner", _get(info, "bitmoji3d.backgroundImage.url") or info.get("squareHeroImageUrl"), src)
    p.set("bio", info.get("bio"), src)
    p.set("followers", info.get("subscriberCount"), src)
    p.set("location", info.get("address"), src)
    p.add_links([info.get("websiteUrl")], src)


@parser("deviantart_2")
async def _deviantart(c: Ctx) -> None:
    meta, src, p = meta_tags(c.body), c.url, c.p
    desc = meta.get("og:description", "")
    for field, word in (("posts", "Artworks"), ("followers", "Followers")):
        m = re.search(word + r":\s*([\d.,]+[KkMm]?)", desc)
        p.set(field, m.group(1) if m else None, src)
    m = re.match(r"(.*?) on DeviantArt", meta.get("og:title", ""))
    p.set("username", m.group(1) if m else None, src)
    p.set("avatar", meta.get("og:image"), src)
    # The "about" module of the page state (escaped JSON): country only. It also
    # carries birth-date parts, which we never read.
    m = re.search(r'\\"about\\":\{\\"username\\":\\"[^"\\]*\\",\\"country\\":\\"([^"\\]+)', c.body)
    p.set("location", m.group(1) if m else None, src)


@parser("kaggle")
async def _kaggle(c: Ctx) -> None:
    meta, src, p = meta_tags(c.body), c.url, c.p
    p.set("name", meta.get("og:title"), src)
    p.set("username", meta.get("og:username"), src)
    p.set("avatar", meta.get("twitter:image") or meta.get("og:image"), src)


@parser("imgflip")
async def _imgflip(c: Ctx) -> None:
    b, src, p = c.body, c.url, c.p
    m = re.search(r"User (\S+) on Imgflip", meta_tags(b).get("description", ""))
    p.set("username", m.group(1) if m else None, src)
    m = re.search(r'id="user-joined">Joined (\d{4}-\d{2}-\d{2})', b)
    p.set("joined", m.group(1) if m else None, src)
    m = re.search(r'([\d,]+) Creations', b)
    p.set("posts", m.group(1) if m else None, src)
    m = re.search(r'id="user-tagline">([^<]+)<', b)
    p.set("bio", m.group(1) if m else None, src)
    m = re.search(r'<img[^>]+id="user-img"[^>]+src="([^"]+)"', b)
    p.set("avatar", m.group(1) if m else None, src)


@parser("cyber_defenders")
async def _cyberdefenders(c: Ctx) -> None:
    # The page embeds its React Server Component payload; profileUser is a JSON object
    # inside an escaped JS string.
    src, p = c.url, c.p
    i = c.body.find('\\"profileUser\\":{')
    if i < 0:
        return
    chunk = c.body[i + len('\\"profileUser\\":'):i + 4000].replace('\\"', '"').replace("\\\\", "\\")
    depth, end = 0, 0
    for idx, ch in enumerate(chunk):
        depth += ch == "{"
        depth -= ch == "}"
        if depth == 0:
            end = idx + 1
            break
    try:
        u = json.loads(chunk[:end])
    except ValueError:
        return
    p.set("username", u.get("username"), src)
    p.set("bio", u.get("title"), src)
    p.set("location", _get(u, "country.name") or _get(u, "country.code"), src)
    p.set("avatar", u.get("image"), src)
    p.set("verified", u.get("is_verified"), src)
    p.set("joined", u.get("joined_at"), src)
    socials = u.get("socials") or {}
    p.add_links([v for v in socials.values() if isinstance(v, str)], src)


@parser("paypal")
async def _paypal(c: Ctx) -> None:
    meta, src, p = meta_tags(c.body), c.url, c.p
    m = re.match(r"Pay (.+?) using PayPal", meta.get("twitter:title") or meta.get("og:title") or "")
    p.set("name", m.group(1) if m else None, src)
    p.set("username", c.username, src)
    # PayPal.Me's public userInfo. displayEmail / displayMobilePhone are never read.
    m = re.search(r'"userInfo":(\{[^{}]*\})', c.body)
    try:
        info = json.loads(m.group(1)) if m else {}
    except ValueError:
        info = {}
    p.set("name", info.get("displayName"), src)
    p.set("location", info.get("displayAddress"), src)
    p.set("avatar", info.get("profilePhotoUrl"), src)
    p.add_links([info.get("website"), info.get("facebookUrl"),
                 info.get("instagramUsername") and f"https://www.instagram.com/{info['instagramUsername']}",
                 info.get("twitterHandle") and f"https://x.com/{info['twitterHandle']}"], src)


@parser("chocolatey")
async def _chocolatey(c: Ctx) -> None:
    b, src, p = c.body, c.url, c.p
    p.set("username", meta_tags(b).get("og:title"), src)
    m = re.search(r"(?:Member since|Joined)[^0-9A-Za-z]{0,40}([A-Z][a-z]+ \d{1,2}, \d{4}|\d{4}-\d{2}-\d{2})", b)
    p.set("joined", m.group(1) if m else None, src)


@parser("medium_2")
async def _medium(c: Ctx) -> None:
    b, src, p = c.body, c.url, c.p
    m = re.search(r"<title><!\[CDATA\[Stories by (.+?) on Medium\]\]></title>", b)
    p.set("name", m.group(1) if m else None, c.probe_url)
    p.set("username", c.username, src)
    m = re.search(r"<image>\s*<url>([^<]+)</url>", b)
    p.set("avatar", m.group(1) if m else None, c.probe_url)
    dates = re.findall(r"<pubDate>([^<]+)</pubDate>", b)
    if dates:
        from .fields import to_iso
        p.set("last_active", max(filter(None, (to_iso(d) for d in dates)), default=None), c.probe_url)


@parser("tryhackme", "discord_2")
async def _existence_only(c: Ctx) -> None:
    """A badge image / a "taken" flag: existence only, no profile data to read."""
    return None
