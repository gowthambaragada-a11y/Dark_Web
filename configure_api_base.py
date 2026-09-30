"""
configure_api_base.py
=====================

Point the static dashboard at a separately-hosted API.

GitHub Pages serves static files only, so when the dashboard is published there
and the API lives on Render (or anywhere else), the page needs to be told where
/api/* actually is. This writes that one constant for you:

    python configure_api_base.py https://anvaya-deanon.onrender.com
    python configure_api_base.py --check                 # show current value
    python configure_api_base.py --reset                 # back to same-origin
    python configure_api_base.py https://host --verify    # then ping /api/health

Resolution order in static/index.html is:

    ?api=<url>  >  window.ANVAYA_API_BASE  >  DEFAULT_API_BASE  >  same origin

Leave DEFAULT_API_BASE empty when main.py serves the page itself -- that is the
single-origin case and needs no configuration at all.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

TARGET = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "static", "index.html")
DECL = re.compile(r"^(const DEFAULT_API_BASE = )'([^']*)'(;.*)$", re.M)


def read_base(text: str) -> str:
    m = DECL.search(text)
    if not m:
        sys.exit("error: DEFAULT_API_BASE declaration not found in "
                 f"{TARGET}; restore it before running this script.")
    return m.group(2)


def normalise(raw: str) -> str:
    """Accept sloppy input and return a clean origin with no trailing slash."""
    url = (raw or "").strip().strip("\"'").rstrip("/")
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    scheme, _, host = url.partition("://")
    if scheme not in ("http", "https"):
        sys.exit(f"error: unsupported scheme {scheme!r}; use http or https.")
    if not host or "/" in host:
        sys.exit(f"error: {raw!r} must be an origin like https://host.tld "
                 "(no path).")
    return f"{scheme}://{host}"


def write_base(url: str) -> None:
    with open(TARGET, "r", encoding="utf-8", newline="") as fh:
        text = fh.read()
    m = DECL.search(text)
    updated = DECL.sub(lambda g: f"{g.group(1)}'{url}'{g.group(3)}", text, count=1)
    with open(TARGET, "w", encoding="utf-8", newline="") as fh:
        fh.write(updated)
    print(f"  DEFAULT_API_BASE: {m.group(2) or '(empty)'} -> {url or '(empty)'}")


def verify(url: str) -> int:
    if not url:
        print("  --verify needs a base; pass a URL or set one first.")
        return 1
    health = f"{url}/api/health"
    try:
        with urllib.request.urlopen(health, timeout=20) as r:
            body = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"  FAIL  GET {health} -> HTTP {e.code}")
        print("        The service may still be deploying, or the URL is wrong.")
        return 1
    except Exception as e:                                    # noqa: BLE001
        print(f"  FAIL  GET {health} -> {e}")
        return 1

    graph = body.get("graph", {})
    print(f"  OK    GET {health} -> 200")
    print(f"        status={body.get('status')} personas={body.get('personas')} "
          f"posts={body.get('posts')}")
    print(f"        graph={graph.get('nodes')} nodes / {graph.get('edges')} edges")
    if body.get("status") != "operational":
        print("        WARNING: health status is not 'operational'.")
        return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Set the dashboard's API base for a split deployment.")
    ap.add_argument("url", nargs="?",
                    help="API origin, e.g. https://anvaya-deanon.onrender.com")
    ap.add_argument("--reset", action="store_true",
                    help="clear the base (single-origin deploy)")
    ap.add_argument("--check", action="store_true",
                    help="print the current value and exit")
    ap.add_argument("--verify", action="store_true",
                    help="after setting, GET <base>/api/health and report")
    args = ap.parse_args()

    with open(TARGET, "r", encoding="utf-8", newline="") as fh:
        current = read_base(fh.read())

    if args.check:
        print(f"DEFAULT_API_BASE = {current or '(empty -> same origin)'}")
        return 0

    if args.reset:
        write_base("")
        return verify("") if args.verify else 0

    if not args.url:
        ap.error("give a URL, or use --reset / --check")

    url = normalise(args.url)
    write_base(url)
    if args.verify:
        return verify(url)
    print("  Next: commit static/index.html and push for the change to go live.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())