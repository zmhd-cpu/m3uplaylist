# JioTV playlists

Three auto-updating M3U playlists, regenerated every 2 hours by GitHub Actions
and committed to the root of the `main` branch:

- `jiotvplus.m3u`
- `jiotvplus2.m3u`
- `jiotvplus3.m3u`

Each file's first lines include an `#DATE:` marker from the upstream service,
which is a handy way to see how fresh a given copy is.

## How it works

`jiotv.py` generates the short-lived `x-test` request header locally (a sealed
UTC timestamp) and decrypts the sealed response with the same key derivation
used by the app. No browser, proxy, or Selenium/Playwright is required.

## Configuration

Endpoints and key material are **not** stored in this repository. They are
provided as GitHub Actions secrets:

| Secret | Purpose |
| --- | --- |
| `JIOTV_KEY` | base64 key material |
| `JIOTV_URL1` | first endpoint -> `jiotvplus.m3u` |
| `JIOTV_URL2` | second endpoint -> `jiotvplus2.m3u` |
| `JIOTV_URL3` | third endpoint -> `jiotvplus3.m3u` |

Additional `JIOTV_URL4`, ... values are supported and produce
`jiotvplus4.m3u`, etc.

## Local use

```sh
python -m venv .venv
.venv/bin/pip install -r requirements.txt
JIOTV_KEY=... JIOTV_URL1=... .venv/bin/python jiotv.py --dir out
```
