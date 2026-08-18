# GHunt Setup Guide

GHunt extracts deep Google account intelligence from a Gmail address: GAIA ID, display
name, profile photo, YouTube channel, public Drive files, Maps review history, active
Google services, and location hints. It authenticates via browser session cookies rather
than an API key.

## Prerequisites

- Python 3.11+
- A Google account you can use to log in via browser

## 1. Install the GHunt extra

```bash
pip install "mailaccess[ghunt]"
```

Or if you manage dependencies manually:

```bash
pip install ghunt>=2.3
```

## 2. Install the companion browser extension

GHunt's login flow captures cookies from your browser session. Install the companion
extension for your browser:

- **Chrome / Edge**: search the Chrome Web Store for "GHunt Companion"
- **Firefox**: search Mozilla Add-ons for "GHunt Companion"

The extension intercepts the OAuth tokens that `ghunt login` needs.

## 3. Run `ghunt login`

```bash
ghunt login
```

GHunt will open a browser tab. Sign into the Google account you want to use as the
authenticating session, then click the GHunt Companion extension icon and copy the
token it shows. Paste it back into the terminal when prompted.

GHunt writes a base64 credentials file to disk. On ghunt 2.x the default location is
`~/.malfrats/ghunt/creds.m` (older builds used `~/.config/ghunt/creds.m`). Note the
file is a base64 blob, not JSON — point `GHUNT_CREDS_PATH` at it directly.

## 4. Set the credentials path in `.env`

```dotenv
ENABLE_GHUNT=true
GHUNT_CREDS_PATH=/home/you/.malfrats/ghunt/creds.m
```

Use the exact path printed by `ghunt login` at the end of the setup.

## 5. Verify

Run a test investigation against a Gmail address and confirm the `ghunt` module
appears in the results with `status: success`.

## Cookie expiry

Google session cookies expire. When the `ghunt` module starts returning errors like
`"unauthorized"` or `"cookie expired"`, repeat step 3 (`ghunt login`) and update
the credentials file at the path set in `GHUNT_CREDS_PATH`. No other configuration
change is needed.

## Supported domains

The module runs only against:

- `@gmail.com`
- `@googlemail.com`
- Any domain whose MX records resolve through Google (Google Workspace)

Investigations against other domains skip the module automatically.

## Privacy and legal

Use GHunt only against accounts you have authorization to investigate. Public OSINT
does not override privacy laws or platform terms of service. Always operate within the
scope of your engagement or research authorization.
