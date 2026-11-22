#!/usr/bin/env python3
"""Fetch Cricfy JioTV playlists and decrypt them to M3U files.

All endpoint URLs and the key material are supplied through environment
variables (GitHub Secrets in Actions). Nothing sensitive lives in this file.

Required environment variables:
    JIOTV_KEY      base64 key recovered from libnative-lib.so
    JIOTV_URL1     first playlist URL     -> jiotvplus.m3u
    JIOTV_URL2     second playlist URL    -> jiotvplus2.m3u
    JIOTV_URL3     third playlist URL     -> jiotvplus3.m3u
    (further JIOTV_URLn values are supported and named jiotvplusN.m3u)

The `x-test` header is a short-lived, AES-GCM-sealed UTC timestamp generated
locally here, so no browser / Selenium / Playwright is needed.

    x-test = "CFP1." + base64url_no_padding(
        salt[16] + nonce[12] + AES-GCM(key, timestamp, aad=b"CFP1") + tag[16])

    key = HMAC_SHA256(HMAC_SHA256(salt, JIOTV_KEY), b"cricfy-playlist-v1\\x01")

Response bodies use the same envelope, with the playlist text as plaintext.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "CFP1."
AAD = b"CFP1"
INFO = b"cricfy-playlist-v1\x01"

_key_b64 = os.environ.get("JIOTV_KEY", "").strip()
if _key_b64:
    # Some secret stores trim trailing '=' padding; restore it if needed.
    _key_b64 += "=" * (-len(_key_b64) % 4)
HARDCODED_KEY = base64.b64decode(_key_b64) if _key_b64 else None

# Exact headers seen on the wire. `Host` and `Connection` are added by requests.
HEADERS = {
    "Accept": "*/*",
    "User-Agent": (
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/155.0.0.0 Mobile Safari/537.36"
    ),
    "x-test": "",  # filled per request
    "Cache-Control": "no-cache, no-store",
    "Accept-Encoding": "gzip",
}


def configured_urls() -> list[tuple[str, str]]:
    """Return (name, url) pairs from JIOTV_URL1, JIOTV_URL2, ... env vars."""
    pairs = []
    for index in range(1, 20):
        url = os.environ.get(f"JIOTV_URL{index}")
        if not url:
            break
        name = "jiotvplus" if index == 1 else f"jiotvplus{index}"
        pairs.append((name, url))
    return pairs


# --------------------------------------------------------------------------
# Transport (the worker only serves India / residential IPs; GitHub's US
# runners get redirected to YouTube, so we route through a fresh India proxy).
# --------------------------------------------------------------------------
PROXY_SOURCES = (
    "https://proxylist.geonode.com/api/proxy-list"
    "?limit=40&page=1&sort_by=latency&sort_type=asc"
    "&country=IN&protocols=http",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/"
    "proxies/countries/IN/data.txt",
)


def proxy_candidates() -> list[dict | None]:
    """Direct connection first, then freshly scraped India HTTP proxies.

    Direct works from an India-based host; proxies let cloud runners (whose
    egress is geo-blocked) reach the same endpoints. Lists are fetched every
    run so dead proxies never get baked into a secret.
    """
    candidates: list[dict | None] = [None]

    for source in PROXY_SOURCES:
        try:
            resp = requests.get(source, timeout=20)
            if "geonode" in source:
                items = [(i.get("ip"), i.get("port"))
                         for i in resp.json().get("data", [])]
            else:
                items = []
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line.startswith("http://"):
                        host = line[7:].split("/")[0]
                        if ":" in host:
                            items.append(tuple(host.rsplit(":", 1)))
            for ip, port in items:
                if ip and port:
                    url = f"http://{ip}:{port}"
                    candidates.append({"http": url, "https": url})
        except (requests.RequestException, ValueError) as exc:
            print(f"  proxy source unavailable: {exc}", file=sys.stderr)

    # De-duplicate while keeping order; cap to keep screening quick.
    seen, unique = set(), []
    for px in candidates:
        key = px.get("https") if px else "direct"
        if key not in seen:
            seen.add(key)
            unique.append(px)
    return unique[:40]


def screen_proxies(url: str, candidates: list[dict | None]) -> list[dict | None]:
    """Return only candidates that actually return a usable playlist."""
    def usable(px: dict | None) -> dict | None:
        try:
            headers = dict(HEADERS, **{"x-test": make_x_test()})
            resp = requests.get(url, headers=headers, proxies=px or {},
                                timeout=15, allow_redirects=False)
            if resp.status_code == 200 and resp.text.strip():
                decode_playlist(resp.text)  # validates CFP1/plaintext
                return px
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        working = [px for px in pool.map(usable, candidates) if px is not None]
    return working


# --------------------------------------------------------------------------
# Crypto helpers
# --------------------------------------------------------------------------
def b64url_encode(raw: bytes) -> str:
    """Base64url, unpadded (Android Base64.URL_SAFE | NO_WRAP | NO_PADDING)."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url (padding is restored here)."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def derive_key(salt: bytes) -> bytes:
    """Two-step HMAC-SHA256 key derivation used by PlaylistCipher."""
    if HARDCODED_KEY is None:
        raise RuntimeError("JIOTV_KEY environment variable is not set")
    first = hmac.new(salt, HARDCODED_KEY, hashlib.sha256).digest()
    return hmac.new(first, INFO, hashlib.sha256).digest()


def seal(plaintext: bytes) -> str:
    """Seal bytes into a CFP1 token (the app's `seal` / access-token path)."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    ciphertext = AESGCM(derive_key(salt)).encrypt(nonce, plaintext, AAD)
    return PREFIX + b64url_encode(salt + nonce + ciphertext)


def open_token(token: str) -> bytes:
    """Decrypt a CFP1 envelope (the app's `open` path)."""
    if not token.startswith(PREFIX):
        raise ValueError("not a CFP1 token")
    blob = b64url_decode(token[len(PREFIX):])
    if len(blob) < 44:
        raise ValueError("token too short")
    salt, nonce, ciphertext = blob[:16], blob[16:28], blob[28:]
    return AESGCM(derive_key(salt)).decrypt(nonce, ciphertext, AAD)


def make_x_test() -> str:
    """Fresh x-test header: the current UTC time sealed exactly like the app."""
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    return seal(stamp.encode("ascii"))


# --------------------------------------------------------------------------
# Playlist
# --------------------------------------------------------------------------
def decode_playlist(content: str) -> str:
    """Return the plaintext M3U, accepting either the sealed blob or plaintext."""
    text = content.strip()
    if text.startswith(("#EXTM3U", "#EXTINF", "#KODIPROP")):
        return text
    if not text.startswith(PREFIX):
        raise ValueError(
            f"unexpected response ({len(text)} chars): {text[:300]!r}"
        )
    return open_token(text).decode("utf-8")


def fetch_playlist(url: str, proxies: list[dict | None]) -> tuple[str, str]:
    """Fetch the URL, trying each working proxy with a fresh x-test."""
    last_error = "unknown"
    for attempt in range(1, 4):
        for px in proxies:
            header = make_x_test()
            headers = dict(HEADERS, **{"x-test": header})
            try:
                resp = requests.get(url, headers=headers, proxies=px or {},
                                    timeout=20, allow_redirects=False)
                if resp.status_code == 200 and resp.text.strip():
                    return decode_playlist(resp.text), header, px
                last_error = f"HTTP {resp.status_code}"
            except (requests.RequestException, ValueError) as exc:
                last_error = str(exc)[:80]
        print(f"  attempt {attempt}/3: {last_error}; retrying with fresh x-test",
              file=sys.stderr)
        time.sleep(1)
    raise RuntimeError(f"could not fetch playlist: {last_error}")


def save_one(name: str, url: str, output_dir: Path,
             proxies: list[dict | None]) -> None:
    """Fetch, decrypt, and save a single playlist."""
    print(f"Fetching {name}")
    playlist, used_header, used_px = fetch_playlist(url, proxies)
    route = used_px["https"] if used_px else "direct"
    print(f"  x-test: {used_header[:24]}... (generated locally)")
    print(f"  route: {route}")

    out = output_dir / f"{name}.m3u"
    out.write_text(playlist, encoding="utf-8")
    channels = sum(1 for line in playlist.splitlines() if line.startswith("#EXTINF"))
    print(f"  saved {len(playlist)} characters, {channels} channels -> {out.name}")

    for line in playlist.splitlines():
        if line.startswith("#DATE:"):
            print(f"  upstream {line}")
            break


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", action="append",
                        help="fetch only this playlist name (repeatable)")
    parser.add_argument("--dir", default=os.environ.get("JIOTV_DIR", "."),
                        help="directory for the .m3u files (default: current)")
    args = parser.parse_args()

    if HARDCODED_KEY is None:
        parser.error("JIOTV_KEY is not set")
    urls = configured_urls()
    if not urls:
        parser.error("no JIOTV_URLn variables are set")

    output_dir = Path(args.dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Screen transports once against the first endpoint, then reuse them.
    candidates = proxy_candidates()
    print(f"Screening {len(candidates)} transport(s) ...")
    working = screen_proxies(urls[0][1], candidates)
    if not working:
        parser.error("no working transport (direct or India proxy) found")
    print(f"Working transport(s): "
          f"{', '.join(px['https'] if px else 'direct' for px in working)}")

    for name, url in urls:
        if args.only and name not in args.only:
            continue
        save_one(name, url, output_dir, working)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
