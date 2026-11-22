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


def fetch_playlist(url: str, x_test: str | None = None) -> tuple[str, str]:
    """Fetch the URL, retrying with a fresh x-test if the server refuses it."""
    last_error = "unknown"
    for attempt in range(1, 4):
        header = make_x_test() if x_test is None else x_test
        headers = dict(HEADERS, **{"x-test": header})
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code == 200 and resp.text.strip():
                # If a rejected token was supplied, don't reuse it on retry.
                return decode_playlist(resp.text), header
            last_error = f"HTTP {resp.status_code} (x-test rejected/expired)"
        except requests.RequestException as exc:
            last_error = str(exc)
        print(f"  attempt {attempt}/3: {last_error}; making a fresh x-test",
              file=sys.stderr)
        x_test = None  # always retry with a newly generated token
        time.sleep(1)
    raise RuntimeError(f"could not fetch playlist: {last_error}")


def save_one(name: str, url: str, output_dir: Path) -> None:
    """Fetch, decrypt, and save a single playlist."""
    print(f"Fetching {name}")
    playlist, used_header = fetch_playlist(url)
    print(f"  x-test: {used_header[:24]}... (generated locally)")

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

    for name, url in urls:
        if args.only and name not in args.only:
            continue
        print(f"  {name}: url_len={len(url)} has_token={'token=' in url}")
        save_one(name, url, output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
