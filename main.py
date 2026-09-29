"""
main.py
=======
FastAPI application for the Anvaya Dark Web De-anonymization Platform.

Run it with:

    uvicorn main:app --reload

then open http://127.0.0.1:8000

Every response is derived from the pre-loaded synthetic corpus in seed_data.py.
No request ever causes outbound network traffic.

API surface
-----------
    GET  /                                dashboard (static/index.html)
    GET  /api/health                      liveness + corpus fingerprint
    GET  /api/meta                        filter vocabularies and methodology
    GET  /api/kpis                        KPI ribbon counters
    GET  /api/actors                      persona list / clusters, filtered
    GET  /api/actors/{handle}             full dossier for one persona
    GET  /api/graph                       Cytoscape.js node/edge payload
    GET  /api/timeline                    corpus event timeline
    POST /api/analyze-persona             live stylometry + attribution sandbox
    GET  /api/samples                     preset samples for the sandbox
    GET  /api/export/{fmt}                csv | json | report  (fmt=dossier/pdf/html)
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import engine
import seed_data

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Set ANVAYA_DB=/path/to/file.db to persist the materialised corpus between
# restarts. The default in-memory database rebuilds from seed_data.py on boot,
# which takes well under a second and keeps the demo stateless.
DB_PATH = os.environ.get("ANVAYA_DB", ":memory:")

app = FastAPI(
    title="Anvaya // Dark Web Threat Actor De-anonymization",
    description=(
        "Offline analytical platform for dark-web threat-actor de-anonymization. "
        "Powered entirely by a synthetic intelligence corpus -- no live scanning, "
        "no Tor crawling, no real identifiers."
    ),
    version="1.4.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

intel = engine.IntelEngine(db_path=DB_PATH)


# --------------------------------------------------------------------------- #
# Shared filter parsing
# --------------------------------------------------------------------------- #


def _split(value: Optional[str]) -> List[str]:
    """Accept both ?category=A,B and repeated ?category=A&category=B."""
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _filtered(filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    return intel.filter_personas(
        category=filters.get("category"),
        source=filters.get("source"),
        min_confidence=filters.get("min_confidence", 0.0),
        start_date=filters.get("start_date"),
        end_date=filters.get("end_date"),
        query=filters.get("q"),
        actor_only=bool(filters.get("actor_only")),
    )


def _filter_params(
    category: Optional[str] = Query(None, description="Comma separated categories"),
    source: Optional[str] = Query(None, description="Comma separated venue names"),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    start_date: Optional[str] = Query(None, description="ISO date, inclusive"),
    end_date: Optional[str] = Query(None, description="ISO date, inclusive"),
    q: Optional[str] = Query(None, description="Free-text search"),
    actor_only: bool = Query(False, description="Collapse personas to one per cluster"),
) -> Dict[str, Any]:
    for label, value in (("start_date", start_date), ("end_date", end_date)):
        if value:
            try:
                datetime.strptime(value, "%Y-%m-%d")
            except ValueError:
                raise HTTPException(400, f"{label} must be an ISO date (YYYY-MM-DD)")
    if start_date and end_date and start_date > end_date:
        raise HTTPException(400, "start_date must not be after end_date")
    return {
        "category": _split(category),
        "source": _split(source),
        "min_confidence": min_confidence,
        "start_date": start_date,
        "end_date": end_date,
        "q": q,
        "actor_only": actor_only,
    }


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #


class AnalyzeRequest(BaseModel):
    text: str = Field(default="", description="Raw darknet post to attribute")
    pgp: Optional[str] = Field(default=None, description="PGP fingerprint or subkey")
    wallet: Optional[str] = Field(default=None, description="BTC or XMR address")
    onion: Optional[str] = Field(
        default=None,
        description=".onion address, TLS serial, cert SHA-256, favicon mmh3 or origin IP",
    )
    posting_hours: Optional[List[int]] = Field(
        default=None, description="UTC hours (0-23) the sample was observed active")
    sample_id: Optional[str] = Field(
        default=None, description="Load a preset from /api/samples instead of raw input")
    label: Optional[str] = Field(default=None, description="Human label for the sample")

    def resolved(self) -> Dict[str, Any]:
        if self.sample_id:
            for sample in intel.corpus["sample_library"]:
                if sample["id"] == self.sample_id:
                    return {
                        "text": sample["text"],
                        "pgp": self.pgp or sample["pgp"],
                        "wallet": self.wallet or sample["wallet"],
                        "onion": self.onion,
                        "posting_hours": self.posting_hours or sample["posting_hours"],
                        "label": self.label or sample["title"],
                    }
            raise HTTPException(404, f"Unknown sample_id '{self.sample_id}'")
        hours = [h for h in (self.posting_hours or []) if 0 <= h <= 23]
        if not (self.text or "").strip() and not (self.pgp or self.wallet or self.onion) \
                and len(hours) < 3:
            raise HTTPException(
                422,
                "Provide raw post text, a PGP key, a wallet address, an onion service, "
                "or at least 3 UTC posting hours, or a sample_id from /api/samples.",
            )
        return {
            "text": self.text,
            "pgp": self.pgp,
            "wallet": self.wallet,
            "onion": self.onion,
            "posting_hours": self.posting_hours,
            "label": self.label or "New sample",
        }


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #


@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {
        "status": "operational",
        "service": "anvaya-deanon",
        "version": app.version,
        "mode": "OFFLINE_ANALYTICAL",
        "corpus_version": intel.corpus["meta"]["corpus_version"],
        "corpus_compiled_at": intel.corpus["meta"]["compiled_at"],
        "storage": "sqlite::memory:" if DB_PATH == ":memory:" else DB_PATH,
        "personas": len(intel.personas),
        "posts": len(intel.posts),
        "graph": {"nodes": intel.graph.number_of_nodes(),
                  "edges": intel.graph.number_of_edges()},
        "utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "disclaimer": intel.corpus["meta"]["disclaimer"],
    }


@app.get("/api/meta")
def meta() -> Dict[str, Any]:
    corpus = intel.corpus["meta"]
    dates = [p["first_seen"] for p in intel.personas] + \
            [p["last_scan_date"] for p in intel.personas]
    return {
        "team": corpus["team"],
        "problem_statement_id": corpus["problem_statement_id"],
        "problem_title": corpus["problem_title"],
        "disclaimer": corpus["disclaimer"],
        "corpus_version": corpus["corpus_version"],
        "markets": intel.corpus["markets"],
        "categories": corpus["categories"],
        "actor_count": len(intel.actors),
        "persona_count": len(intel.personas),
        "date_bounds": {"min": min(dates), "max": max(dates)},
        "entity_colors": engine.ENTITY_COLORS,
        "category_colors": engine.CATEGORY_COLORS,
        "methodology": {
            "formula": "Score = 1 - prod(1 - weight_i * similarity_i)",
            "channel_weights": engine.CHANNEL_WEIGHTS,
            "subvector_weights": engine.SUBVECTOR_WEIGHTS,
            "soft_match_cap": engine.SOFT_MATCH_CAP,
            "hard_match_ceiling": engine.HARD_MATCH_CEILING,
            "min_margin": engine.MIN_MARGIN,
            "reporting_floor": engine.MIN_FLOOR,
            "calibration": (
                "Continuous vectors are z-scored against a cross-actor, leave-one-out "
                "impostor null and capped at 4 sigma (3 sigma for the circadian "
                "circular phase-shift null). The UI reports the z-score alongside every "
                "similarity so each number is auditable against a stated null."
            ),
            "missing_feature_policy": (
                "Handcrafted habit features that a pasted sample cannot express (emoji, "
                "trailing whitespace, transliteration typos) sit at the corpus floor and "
                "are masked rather than scored as absence."
            ),
        },
        "cluster_resolution": intel.resolution,
    }


@app.get("/api/kpis")
def kpis() -> Dict[str, Any]:
    return intel.kpis()


@app.get("/api/actors")
def list_actors(
    filters: Dict[str, Any] = Depends(_filter_params),
) -> Dict[str, Any]:
    personas = _filtered(filters)
    return {
        "count": len(personas),
        "filters_applied": filters,
        "kpis": intel.kpis(),
        "personas": personas,
        "actors": intel.actors,
        "markets": intel.corpus["markets"],
    }


@app.get("/api/actors/{handle}")
def get_actor(handle: str) -> Dict[str, Any]:
    persona = intel.persona_by_handle.get(handle)
    if persona is None:
        for row in intel._rows("SELECT * FROM personas WHERE id = ?", (handle,)):
            persona = row
            break
    if persona is None:
        raise HTTPException(404, f"No persona named '{handle}'")
    full = intel._rows(
        "SELECT p.*, a.codename AS actor_codename, a.resolution_method, "
        "a.attribution_note, m.name AS source_name, m.kind AS source_kind, "
        "m.status AS source_status FROM personas p JOIN actors a ON a.id = p.actor_id "
        "JOIN markets m ON m.id = p.source_id WHERE p.id = ? OR p.handle = ?",
        (handle, handle),
    )
    if not full:
        raise HTTPException(404, f"No persona named '{handle}'")
    detail = intel.hydrate_persona(full[0])
    siblings = [intel.hydrate_persona(row) for row in intel._rows(
        "SELECT p.*, a.codename AS actor_codename, a.resolution_method, "
        "m.name AS source_name, m.kind AS source_kind, m.status AS source_status "
        "FROM personas p JOIN actors a ON a.id = p.actor_id "
        "JOIN markets m ON m.id = p.source_id "
        "WHERE p.actor_id = ? AND p.id != ?", (full[0]["actor_id"], full[0]["id"]))]
    return {"persona": detail, "cluster_siblings": siblings}


@app.get("/api/graph")
def graph(
    filters: Dict[str, Any] = Depends(_filter_params),
    include_selector_nodes: bool = Query(True),
    soft_links: bool = Query(True, description="Include stylometry/circadian/contested edges"),
) -> Dict[str, Any]:
    personas = _filtered(filters)
    payload = intel.graph_payload(
        persona_ids=[p["id"] for p in personas],
        include_selector_nodes=include_selector_nodes,
        soft_links=soft_links,
    )
    payload["filters_applied"] = filters
    payload["legend"] = {
        "nodes": {k: v for k, v in engine.ENTITY_COLORS.items()},
        "edges": {
            "PERSONA_OF": "persona belongs to actor cluster",
            "USES_PGP": "persona signs with this PGP key",
            "CONTROLS_WALLET": "persona controls this wallet",
            "CO_SPENT_TX": "wallets share common transaction inputs",
            "INFRA_MATCH": "onion services share an infrastructure artifact",
            "INFRA_MATCH_CONTESTED": "cross-actor artifact collision (false positive)",
            "STYLOMETRY_LINK": "character n-gram cosine above threshold",
            "CIRCADIAN_LINK": "24h UTC activity windows are correlated",
            "ORIGIN_OF": "onion service resolves to this clearnet origin",
            "OPERATES": "persona runs this onion service",
            "CONTACTS_VIA": "persona reachable on this messaging selector",
        },
    }
    return payload


@app.get("/api/timeline")
def timeline() -> Dict[str, Any]:
    return {
        "events": intel._rows(
            "SELECT t.*, p.handle, a.codename AS actor FROM timeline t "
            "LEFT JOIN personas p ON p.id = t.persona_id "
            "LEFT JOIN actors a ON a.id = p.actor_id ORDER BY t.ts"),
        "markets": intel.corpus["markets"],
    }


@app.get("/api/samples")
def samples() -> Dict[str, Any]:
    return {
        "samples": [
            {k: v for k, v in s.items() if k != "text"} | {
                "text_preview": s["text"][:160],
                "text_length": len(s["text"]),
            }
            for s in intel.corpus["sample_library"]
        ]
    }


@app.get("/api/samples/{sample_id}")
def sample_detail(sample_id: str) -> Dict[str, Any]:
    for sample in intel.corpus["sample_library"]:
        if sample["id"] == sample_id:
            return {"sample": sample}
    raise HTTPException(404, f"Unknown sample '{sample_id}'")


@app.post("/api/analyze-persona")
def analyze_persona(request: AnalyzeRequest) -> Dict[str, Any]:
    payload = request.resolved()
    return intel.analyze(
        text=payload["text"],
        pgp=payload["pgp"],
        wallet=payload["wallet"],
        onion=payload["onion"],
        posting_hours=payload["posting_hours"],
        sample_label=payload["label"],
    )


@app.get("/api/export/{fmt}")
def export(
    fmt: str,
    filters: Dict[str, Any] = Depends(_filter_params),
) -> Response:
    fmt = fmt.lower()
    if fmt not in {"csv", "json", "report", "dossier", "pdf", "html"}:
        raise HTTPException(
            400, "format must be one of: csv, json, report (alias: dossier, pdf, html)")
    personas = _filtered(filters)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    scope = ("all-personas" if not any(filters.get(k) for k in
                                       ("category", "source", "q", "start_date", "end_date"))
             else "filtered")

    if fmt == "csv":
        body = intel.to_csv(personas)
        if not body:
            raise HTTPException(404, "No personas matched the current filter.")
        return Response(
            content=body, media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition":
                     f'attachment; filename="anvaya-{scope}-{stamp}.csv"'})

    if fmt == "json":
        return Response(
            content=intel.to_json(personas), media_type="application/json; charset=utf-8",
            headers={"Content-Disposition":
                     f'attachment; filename="anvaya-{scope}-{stamp}.json"'})

    title = ("Dark Web Threat Actor De-anonymization // Investigative Dossier"
             if scope == "all-personas"
             else f"Filtered Intelligence Dossier // {len(personas)} record(s)")
    html = intel.to_dossier(personas, title)
    disposition = ("inline" if fmt in {"report", "html"}
                   else f'attachment; filename="anvaya-{scope}-{stamp}.html"')
    return Response(
        content=html, media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": disposition})


# --------------------------------------------------------------------------- #
# Static dashboard
# --------------------------------------------------------------------------- #

os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def index() -> Response:
    path = os.path.join(STATIC_DIR, "index.html")
    if not os.path.exists(path):
        raise HTTPException(500, "static/index.html is missing from the project root")
    with open(path, encoding="utf-8") as handle:
        return Response(content=handle.read(), media_type="text/html; charset=utf-8")


@app.get("/favicon.ico")
def favicon() -> Response:
    return Response(status_code=204)


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
