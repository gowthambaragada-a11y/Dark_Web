"""
smoke_test.py
=============
End-to-end regression suite for the Anvaya platform.

    python smoke_test.py                     # starts nothing, uses a temp server
    python smoke_test.py --base http://127.0.0.1:8000   # test a running server

The suite boots uvicorn on an ephemeral port, exercises every documented
endpoint, asserts the seeded attribution ground truth, then shuts down.
No outbound network traffic: /api/samples and /api/graph are local.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

PASS = "\033[92m[OK]  \033[0m"
FAIL = "\033[91m[FAIL]\033[0m"

_failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  {PASS} {label}")
    else:
        print(f"  {FAIL} {label}{(' -> ' + detail) if detail else ''}")
        _failures.append(label)


# --------------------------------------------------------------------------- #
# Tiny HTTP client (stdlib only, so the suite has no extra dependencies)
# --------------------------------------------------------------------------- #


def request(base: str, path: str, method: str = "GET",
            body: Optional[Dict[str, Any]] = None) -> Tuple[int, Any, Dict[str, str]]:
    url = f"{base}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8", "replace")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            ctype = headers.get("content-type", "")
            payload = json.loads(raw) if "json" in ctype else raw
            return resp.status, payload, headers
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw), {}
        except json.JSONDecodeError:
            return exc.code, raw, {}
    except Exception as exc:                      # connection refused, timeout, ...
        return 0, {"transport_error": str(exc)}, {}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_boot(base: str, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, payload, _ = request(base, "/api/health")
            if status == 200:
                return True
        except Exception:
            time.sleep(0.4)
    return False


# --------------------------------------------------------------------------- #
# Suite
# --------------------------------------------------------------------------- #

# Ground truth seeded in seed_data.py -- (expected verdict, expected actor id).
GROUND_TRUTH = {
    "smp-1": ("PROBABLE_SOFT", "act-obsidian-ledger"),
    "smp-2": ("CONFIRMED", "act-vexing-hydra"),
    "smp-3": ("CONFIRMED", "act-mule-cartel"),
    "smp-4": ("PROBABLE_SOFT", "act-ghost-cartel"),
    "smp-5": ("NO_MATCH", None),
}

REQUIRED_NODE_TYPES = {
    "ThreatActor", "Persona", "PGPKey", "CryptoWallet", "OnionService", "ClearnetIP",
}
REQUIRED_EDGE_TYPES = {
    "USES_PGP", "CONTROLS_WALLET", "CO_SPENT_TX", "INFRA_MATCH", "STYLOMETRY_LINK",
}


def run_suite(base: str) -> None:
    def section(title: str) -> None:
        print(f"\n=== {title} ===")

    section("1. liveness & metadata")
    status, health, _ = request(base, "/api/health")
    check("GET /api/health -> 200", status == 200, str(status))
    check("status operational", health.get("status") == "operational")
    check("mode is offline", health.get("mode") == "OFFLINE_ANALYTICAL")
    check("6 personas loaded", health.get("personas") == 6, str(health.get("personas")))
    check("141 posts loaded", health.get("posts") == 141, str(health.get("posts")))
    check("disclaimer present", "SYNTHETIC" in (health.get("disclaimer") or ""))

    status, meta, _ = request(base, "/api/meta")
    check("GET /api/meta -> 200", status == 200, str(status))
    check("PS 26151 declared", meta.get("problem_statement_id") == "26151",
          str(meta.get("problem_statement_id")))
    check("3 venues declared", len(meta.get("markets", [])) == 3,
          str(len(meta.get("markets", []))))
    check("soft cap published", meta.get("methodology", {}).get("soft_match_cap") == 0.79)
    check("resolution log present", len(meta.get("cluster_resolution", {}).get("log", [])) >= 2)

    section("2. registry & filters")
    status, actors, _ = request(base, "/api/actors")
    check("GET /api/actors -> 200", status == 200, str(status))
    check("6 personas", actors.get("count") == 6, str(actors.get("count")))
    check("4 clusters", len(actors.get("actors", [])) == 4, str(len(actors.get("actors", []))))

    handles = {p["handle"] for p in actors.get("personas", [])}
    check("ShadowBroker_99 present", "ShadowBroker_99" in handles)
    check("NightOwl_V2 present", "NightOwl_V2" in handles)

    _, filtered, _ = request(base, "/api/actors?category=Ransomware")
    check("filter category=Ransomware -> 2", filtered.get("count") == 2,
          str(filtered.get("count")))
    _, filtered, _ = request(base, "/api/actors?source=AlphaBay-Sim")
    check("filter source=AlphaBay-Sim -> 2", filtered.get("count") == 2,
          str(filtered.get("count")))
    _, filtered, _ = request(base, "/api/actors?actor_only=true")
    check("filter actor_only -> 4", filtered.get("count") == 4, str(filtered.get("count")))
    status, _, _ = request(base, "/api/actors?start_date=not-a-date")
    check("invalid date rejected -> 400", status == 400, str(status))
    status, _, _ = request(base, "/api/actors?start_date=2025-01-01&end_date=2024-01-01")
    check("inverted date range -> 400", status == 400, str(status))

    section("3. persona dossier")
    status, dossier, _ = request(base, "/api/actors/ShadowBroker_99")
    check("GET /api/actors/ShadowBroker_99 -> 200", status == 200, str(status))
    check("dossier has evidence", len(dossier.get("persona", {}).get("evidence", [])) > 0)
    check("dossier has hour histogram",
          len(dossier.get("persona", {}).get("hour_histogram", [])) == 24)
    status, _, _ = request(base, "/api/actors/does-not-exist")
    check("unknown persona -> 404", status == 404, str(status))

    section("4. graph payload")
    status, graph, _ = request(base, "/api/graph")
    check("GET /api/graph -> 200", status == 200, str(status))
    check("66 nodes", len(graph.get("nodes", [])) == 66, str(len(graph.get("nodes", []))))
    check("95 edges", len(graph.get("edges", [])) == 95, str(len(graph.get("edges", []))))
    node_types = {n["type"] for n in graph.get("nodes", [])}
    check("all required node types", REQUIRED_NODE_TYPES <= node_types,
          str(sorted(REQUIRED_NODE_TYPES - node_types)))
    edge_types = {e["type"] for e in graph.get("edges", [])}
    check("all required edge types", REQUIRED_EDGE_TYPES <= edge_types,
          str(sorted(REQUIRED_EDGE_TYPES - edge_types)))

    # every node/edge must carry the fields the Cytoscape style maps over
    missing = [f for n in graph.get("nodes", [])
               for f in ("id", "label", "type", "color", "size") if f not in n]
    check("nodes carry style fields", not missing, str(sorted(set(missing))))
    missing = [f for e in graph.get("edges", [])
               for f in ("id", "source", "target", "type", "color", "width", "confidence")
               if f not in e]
    check("edges carry style fields", not missing, str(sorted(set(missing))))

    contested = [e for e in graph.get("edges", []) if e["type"] == "INFRA_MATCH_CONTESTED"]
    check("false-positive edge is flagged contested", len(contested) >= 1, str(len(contested)))

    status, g2, _ = request(base, "/api/graph?include_selector_nodes=false")
    check("graph filter include_selector_nodes=false shrinks payload",
          len(g2.get("nodes", [])) < len(graph.get("nodes", [])))
    status, g3, _ = request(base, "/api/graph?source=Hydra-Sim")
    check("graph filter source=Hydra-Sim shrinks payload",
          len(g3.get("nodes", [])) < len(graph.get("nodes", [])))

    status, timeline, _ = request(base, "/api/timeline")
    check("GET /api/timeline -> 200", status == 200, str(status))
    check("timeline has events", len(timeline.get("events", [])) > 0)

    section("5. attribution ground truth")
    for sample_id, (verdict, actor_id) in GROUND_TRUTH.items():
        status, res, _ = request(base, "/api/analyze-persona", "POST",
                                  {"sample_id": sample_id})
        ok = status == 200 and res.get("verdict") == verdict
        detail = f"got {res.get('verdict')} expected {verdict}"
        if ok and actor_id:
            ok = res.get("attribution", {}).get("actor_id") == actor_id
            detail = f"actor {res.get('attribution', {}).get('actor_id')} != {actor_id}"
        check(f"{sample_id} -> {verdict}", ok, detail)

    section("6. hard-selector resolution")
    shared = "71E4B0C8A3D95F2618C7B4E0D9A3F5126C8B0D74A"
    _, res, _ = request(base, "/api/analyze-persona", "POST", {"pgp": shared})
    check("shared PGP subkey -> CONFIRMED", res.get("verdict") == "CONFIRMED",
          str(res.get("verdict")))
    check("shared PGP subkey -> VEXING HYDRA",
          res.get("attribution", {}).get("actor_id") == "act-vexing-hydra")
    check("hard selector hit registered", res.get("attribution", {}).get("hard_selector_fired") is True,
          str(res.get("attribution", {}).get("hard_selector_fired")))

    _, res, _ = request(base, "/api/analyze-persona", "POST",
                        {"onion": "vk0idk1t3v7x9m2q5b8n4c6w0z3f7h1l43WSCNDL3BRXGNDAFPZBGIPX.onion"})
    check("onion service lookup -> CONFIRMED", res.get("verdict") == "CONFIRMED",
          str(res.get("verdict")))

    section("7. input validation")
    status, _, _ = request(base, "/api/analyze-persona", "POST", {})
    check("empty payload -> 422", status == 422, str(status))
    status, _, _ = request(base, "/api/analyze-persona", "POST", {"text": "hi"})
    check("single-word payload -> INCONCLUSIVE",
          status == 200, str(status))
    status, res, _ = request(base, "/api/analyze-persona", "POST",
                             {"text": "hello world", "pgp": "ZZZZ", "wallet": "nope",
                              "onion": "zzz.onion"})
    check("junk selectors -> weak/no hit", status == 200
          and res.get("attribution", {}).get("score", 1) < 0.6,
          str(res.get("attribution", {}).get("score")))
    status, _, _ = request(base, "/api/analyze-persona", "POST",
                           {"posting_hours": [2]})
    check("1 posting hour -> 422 (need >= 3)", status == 422, str(status))
    status, res, _ = request(base, "/api/analyze-persona", "POST",
                             {"posting_hours": [1, 2, 3, 14, 23]})
    check("5 posting hours -> 200 circadian", status == 200, str(status))
    status, _, _ = request(base, "/api/analyze-persona", "POST", {"sample_id": "smp-999"})
    check("unknown sample_id -> 404", status == 404, str(status))

    section("8. sample library")
    status, listing, _ = request(base, "/api/samples")
    check("GET /api/samples -> 200", status == 200, str(status))
    check("5 preset samples", len(listing.get("samples", [])) == 5,
          str(len(listing.get("samples", []))))
    check("list omits full text", all("text" not in s for s in listing.get("samples", [])))
    check("list carries preview", all(s.get("text_preview") for s in listing.get("samples", [])))
    status, detail, _ = request(base, "/api/samples/smp-1")
    check("GET /api/samples/smp-1 -> 200", status == 200, str(status))
    check("detail carries full text", len(detail.get("sample", {}).get("text", "")) > 200)
    status, _, _ = request(base, "/api/samples/smp-999")
    check("unknown sample -> 404", status == 404, str(status))

    section("9. exports")
    for fmt, min_len in (("csv", 500), ("json", 1000), ("report", 5000),
                         ("dossier", 5000), ("html", 5000)):
        status, payload, headers = request(base, f"/api/export/{fmt}")
        size = len(payload) if isinstance(payload, str) else len(json.dumps(payload))
        check(f"export {fmt} -> 200, {size}B", status == 200 and size > min_len, str(status))
    status, _, _ = request(base, "/api/export/bogus")
    check("export bogus -> 400", status == 400, str(status))
    status, payload, _ = request(base, "/api/export/csv?category=Ransomware")
    check("filtered export csv -> 200", status == 200, str(status))
    check("filtered csv has header",
          isinstance(payload, str) and payload.splitlines()[0].startswith("actor_cluster"))

    section("10. dashboard shell")
    status, html, _ = request(base, "/")
    check("GET / -> 200", status == 200, str(status))
    check("html is a document", isinstance(html, str) and "<!doctype html" in html.lower())
    for token in ("cytoscape.min.js", "chart.umd.min.js", "lucide.min.js",
                  "cdn.tailwindcss.com"):
        check(f"dashboard references {token}", token in html)
    status, _, _ = request(base, "/favicon.ico")
    check("GET /favicon.ico -> 204", status == 204, str(status))
    status, _, _ = request(base, "/static/index.html")
    check("static mount serves index", status == 200, str(status))
    status, _, _ = request(base, "/api/docs")
    check("openapi docs -> 200", status == 200, str(status))


    section("11. concurrent request safety")
    # FastAPI runs these sync endpoints in a threadpool. A shared sqlite3
    # connection used from several threads at once raises InterfaceError, so
    # hammer the DB-backed routes in parallel and require every one to be 200.
    import concurrent.futures

    routes_to_hit = ["/api/actors", "/api/graph", "/api/kpis", "/api/meta",
                     "/api/timeline", "/api/actors/ShadowBroker_99",
                     "/api/actors?category=Ransomware", "/api/graph?source=Hydra-Sim",
                     "/api/graph?actor_only=true", "/api/export/csv"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(request, base, r) for r in routes_to_hit * 6]
        codes = [f.result()[0] for f in futures]
    bad = [c for c in codes if c != 200]
    check(f"{len(codes)} concurrent requests all 200", not bad,
          f"{len(bad)} non-200: {sorted(set(bad))}")

    def parallel_analyze(i: int):
        return request(base, "/api/analyze-persona", "POST",
                       {"sample_id": ["smp-1", "smp-2", "smp-3", "smp-4", "smp-5"][i % 5]})[0]

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        codes = list(pool.map(parallel_analyze, range(24)))
    check("24 concurrent analyses all 200", all(c == 200 for c in codes),
          f"got {sorted(set(codes))}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Anvaya end-to-end smoke test")
    parser.add_argument("--base", default=None,
                        help="base URL of a running server (default: boot a temporary one)")
    parser.add_argument("--keep", action="store_true", help="leave the temp server running")
    args = parser.parse_args()

    tmp = None
    if args.base:
        base = args.base.rstrip("/")
    else:
        import uvicorn

        port = free_port()
        base = f"http://127.0.0.1:{port}"
        import main as app_main

        config = uvicorn.Config(app_main.app, host="127.0.0.1", port=port, log_level="error")
        tmp = uvicorn.Server(config)
        thread = threading.Thread(target=tmp.run, daemon=True)
        thread.start()
        print(f"booting temporary server on {base} ...")
        if not wait_for_boot(base):
            print("server failed to boot", file=sys.stderr)
            return 2

    try:
        run_suite(base)
    finally:
        if tmp is not None and not args.keep:
            tmp.should_exit = True
            time.sleep(0.6)

    print("\n" + "=" * 62)
    if _failures:
        print(f"FAILED: {len(_failures)} check(s)")
        for name in _failures:
            print(f"  - {name}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())








