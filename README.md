# ANVAYA — Dark Web Threat Actor De-anonymization Platform

**Team Anvaya · Smart India Hackathon 2026 · Problem Statement 26151**

An offline analytical platform that de-anonymizes dark-web threat actors by fusing
stylometric, cryptographic, financial and infrastructure signals into a single
attribution score, then visualizes the resulting identity graph.

> **Synthetic corpus only.** There is no live scanning, no Tor crawling and no real
> identifier anywhere in this project. Every persona, key, wallet, `.onion` address
> and clearnet host is fabricated. All IPs are RFC-5737 documentation ranges
> (`198.51.100.0/24`, `203.0.113.0/24`) and all ASNs are RFC-5398 private values
> (`AS64500–AS64599`), so nothing can resolve to a real host.

---

## Quick start

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

Open **http://127.0.0.1:8000**.

The corpus is materialised in-memory on boot (well under a second), so there is no
database to provision and no migration step. To persist it to disk instead:

```bash
ANVAYA_DB=anvaya.db uvicorn main:app --reload     # macOS / Linux
$env:ANVAYA_DB="anvaya.db"; uvicorn main:app       # PowerShell
```

`python main.py` is equivalent to `uvicorn main:app --reload` on port 8000.

---

## What it does

| Capability | Detail |
| --- | --- |
| **Stylometry** | Character 2–4-gram + word 1–2-gram TF-IDF cosine, plus handcrafted orthography, punctuation and topic vectors |
| **Circadian** | 24-bin UTC activity histogram matched by circular phase shift |
| **Hard selectors** | PGP fingerprints and subkeys, BTC/XMR addresses, common-input co-spending clusters, TLS serials, certificate SHA-256, favicon mmh3, origin IP, `.onion` reuse |
| **Cluster resolution** | Union-find over hard-selector links, with behavioural-only merges clearly labelled as such |
| **Graph** | 66 nodes / 95 edges across `ThreatActor`, `Persona`, `PGPKey`, `CryptoWallet`, `OnionService`, `ClearnetIP`, `Market`, `MessagingID`, `TxCluster` |
| **Attribution** | Noisy-OR fusion, z-scored against a cross-actor leave-one-out impostor null |
| **Export** | CSV, JSON, and a printable HTML investigative dossier |

### Scoring

```
Score = 1 - Π (1 - weight_i × similarity_i)
```

Channel weights: `stylometric 0.62`, `formatting 0.30`, `circadian 0.45`,
`crypto 0.94`, `infrastructure 0.90`.

Continuous vectors are z-scored against a leave-one-out impostor null and capped at
4σ (3σ for the circadian null), so a raw cosine of 0.95 against an unrelated actor
is reported near zero. Every number in the UI is shown next to the null it was
measured against.

### Guardrails against false positives

These are deliberate, seeded cases — the point of the project is that unsupervised
attribution fails in identifiable ways:

1. **Soft-match ceiling.** Behavioural merges (`STYLOMETRY_LINK`, `CIRCADIAN_LINK`)
   are capped at `0.79` and can never reach `CONFIRMED`. Only a hard selector can.
2. **Contested infrastructure.** `SHARED_FAVICON_HASH` (`0x7A3C91E4`) is shared by
   two *unrelated* actors; those links are held at 41% and tagged
   `INFRA_MATCH_CONTESTED`.
3. **Margin requirement.** A candidate must beat the runner-up by `0.05` or the
   result is downgraded.
4. **Reporting floor.** Anything below `0.45` is reported as `NO_MATCH` rather
   than being presented as a lead. Below the floor the API returns
   `attribution: null` — it does **not** name a subject. The nearest cluster is
   still reported, in a separate field, so a real lead is never silently lost:

   ```json
   { "verdict": "NO_MATCH",
     "attribution": null,
     "below_floor_best": { "actor": "GHOST CARTEL", "score": 0.4426,
                           "shortfall": 0.0074 } }
   ```

   The dashboard renders this as **No attribution** with a muted note reading
   *"nearest candidate was GHOST CARTEL at 44.3% — 0.7% short of the reporting
   floor. Recorded, not attributed."* Naming a subject while the verdict says
   `NO_MATCH` is exactly the failure mode this project exists to avoid.

5. **Negative control.** Sample `smp-5` is register-shifted and *must not* match.
   It is asserted in `smoke_test.py` to return `attribution: null` — the closest
   cluster it scores against is GHOST CARTEL at `0.4426`, just under the floor.

---

## Seeded scenarios

Six personas resolve into four actor clusters across three simulated venues.

### OBSIDIAN LEDGER — behavioural-only rebrand (`CONFIRMED_SOFT`)

| | `ShadowBroker_99` | `NightOwl_V2` |
| --- | --- | --- |
| Venue | AlphaBay-Sim (seized 2024-03-14) | Dread-Sim (raided 2024-09-02) |
| PGP keys | 3, disjoint | 2, disjoint |
| Wallets | disjoint | disjoint |
| Declared circadian profile | identical, peaks 02:00–04:00 UTC (`r = 1.00`) | identical |
| Resolution | cap 0.79 — never `CONFIRMED` | cap 0.79 |

Merged on stylometry and circadian behaviour alone. There is **no** hard selector,
which is exactly why the score is held below the confirmation threshold.

The two personas are *modelled* with an identical 24-hour activity profile, which is
what the circadian matcher compares. The per-persona posting histogram in the UI is
counted from actual generated posts around that profile, so it is close but not
literally equal — as real data would be.

### VEXING HYDRA — hard-selector continuity (`CONFIRMED_HARD`)

`V0idKite` (AlphaBay-Sim) → `IceVex_0x` (Hydra-Sim) share PGP subkey
`71E4B0C8A3D95F2618C7B4E0D9A3F5126C8B0D74A`, transaction cluster `txc-vex-01`, and
the certificate serial `8d31:6f45:2b90:ae17:…` on origin `198.51.100.212`
(`AS64512`).

### MULE CARTEL — financial

`CryptoMule_K` is tied to MULE CARTEL by a common-input co-spending cluster of
payout addresses, not by writing style.

### GHOST CARTEL — the false-positive control

Shares the `0x7A3C91E4` favicon with VEXING HYDRA. The link exists, is rendered,
and is deliberately *not* sufficient to merge the clusters.

---

## API

Interactive docs at **/api/docs**.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Liveness, corpus fingerprint, graph size |
| `GET` | `/api/meta` | Venues, categories, entity colours, methodology constants, cluster-resolution log |
| `GET` | `/api/kpis` | Dashboard counters |
| `GET` | `/api/actors` | Filtered persona list and clusters |
| `GET` | `/api/actors/{handle}` | Full dossier (id or handle) |
| `GET` | `/api/graph` | Cytoscape.js node/edge payload |
| `GET` | `/api/timeline` | Corpus event timeline |
| `GET` | `/api/samples` | Sandbox presets (metadata + preview) |
| `GET` | `/api/samples/{id}` | Sandbox preset with full text |
| `POST` | `/api/analyze-persona` | Attribution sandbox |
| `GET` | `/api/export/{fmt}` | `csv` · `json` · `report` · `dossier` · `html` |

### Filters

Accepted by `/api/actors`, `/api/graph` and `/api/export/{fmt}` — as a
comma-separated list or as a repeated parameter:

`category`, `source`, `min_confidence`, `start_date`, `end_date`, `q`, `actor_only`

```bash
curl "http://127.0.0.1:8000/api/actors?category=Ransomware&min_confidence=0.8"
curl "http://127.0.0.1:8000/api/graph?source=AlphaBay-Sim&soft_links=false"
```

### Attribution sandbox

```bash
curl -X POST http://127.0.0.1:8000/api/analyze-persona \
  -H "Content-Type: application/json" \
  -d '{"sample_id":"smp-2"}'
```

Or with raw input — any combination of `text`, `pgp`, `wallet`, `onion`, `posting_hours`:

```bash
curl -X POST http://127.0.0.1:8000/api/analyze-persona \
  -H "Content-Type: application/json" \
  -d '{"pgp":"71E4B0C8A3D95F2618C7B4E0D9A3F5126C8B0D74A"}'
```

`posting_hours` needs at least 3 entries; on its own the circadian channel needs
enough samples to be meaningful.

### Ground truth for the presets

| Sample | Expected verdict | Actor |
| --- | --- | --- |
| `smp-1` | `PROBABLE_SOFT` | OBSIDIAN LEDGER |
| `smp-2` | `CONFIRMED` | VEXING HYDRA |
| `smp-3` | `CONFIRMED` | MULE CARTEL |
| `smp-4` | `PROBABLE_SOFT` | GHOST CARTEL |
| `smp-5` | `NO_MATCH` | — (negative control; `attribution` is `null`) |

These five rows are asserted on every `smoke_test.py` run, including the
requirement that `smp-5` names no subject at all.

---

## Deployment

### Two ways to deploy

The dashboard is a static page; the intelligence is a FastAPI service. That split
determines which host you need:

| | Backend | Dashboard | Notes |
| --- | --- | --- | --- |
| **A. Render only** (recommended) | Render | Render, same origin | Nothing to configure — relative API URLs just work |
| **B. Render + GitHub Pages** | Render | `*.github.io` | Set one constant so the page knows the API origin |

GitHub Pages **cannot** run the FastAPI backend. It serves static files only. So
in option B, Pages hosts the HTML and Render hosts `/api/*`, and the dashboard
needs to be told where that is.

---

### A. Render only (recommended)

The repository ships a Render blueprint, so this is a no-argument deploy:

1. Push the repository to GitHub.
2. In Render: **New → Blueprint** → select the repo → **Apply**.
3. Render reads `render.yaml`, installs `requirements.txt`, and starts
   `uvicorn main:app --host 0.0.0.0 --port $PORT --workers 1`.

The service serves both the dashboard and the API from one origin, so the
dashboard's relative API URLs work unchanged. It comes up on
`https://anvaya-deanon.onrender.com` (or whatever name is available).

A few things to know on the free tier:

- **Cold starts.** Free services idle out after ~15 minutes and take ~30 s to
  wake. The corpus is rebuilt from `seed_data.py` on every boot (well under a
  second), so there is no database to provision.
- **Health check.** Render polls `/api/health`; it reports corpus size, graph
  dimensions and the storage mode, so it doubles as a smoke test.
- **One worker, on purpose.** The corpus is materialised in-memory per process.
  A single worker keeps the SQLite state and the lock that guards it coherent.
  Raising `--workers` would multiply the corpus in RAM; it is safe (the seed is
  deterministic) but wasteful, and a real multi-worker setup should move to a
  real database first.
- **CDN assets.** Tailwind, Cytoscape.js, Chart.js and Lucide load from public
  CDNs, so the *browser* needs internet on first paint. The API never makes an
  outbound request.

### B. Render (API) + GitHub Pages (dashboard)

Use this only if the dashboard must live on `github.io`. Deploy the API with the
blueprint above, then point the static page at it.

**1. Deploy the API to Render** exactly as in option A.

**2. Tell the page where the API is.** In `static/index.html`:

```js
const DEFAULT_API_BASE = 'https://anvaya-deanon.onrender.com';
```

That is the only line that changes. Every request — boot, filters, dossiers,
the sandbox POST and all five export formats — is routed through `apiUrl()`, so
nothing else needs touching. Leave it as `''` for local dev or a single-origin
Render deploy.

`configure_api_base.py` writes that line for you (it normalises the URL and
refuses anything that is not a bare origin):

```bash
python configure_api_base.py --check
python configure_api_base.py https://anvaya-deanon.onrender.com --verify
python configure_api_base.py --reset      # back to same-origin
```

`--verify` pings `<base>/api/health` and prints corpus size, so you can confirm
the backend is live before pointing the page at it.

Two overrides exist for testing without a rebuild:

- `?api=https://host` — per-request override, useful to compare two backends.
- `window.ANVAYA_API_BASE` — set by an injected `config.js`, if you would rather
  not commit the host.

Resolution order is `?api=` → `window.ANVAYA_API_BASE` → `DEFAULT_API_BASE` →
same origin. If the backend is unreachable the boot screen now names the base it
tried, instead of failing on a bare `404`.

**3. GitHub Pages settings.** The repo carries `.nojekyll`, which switches Jekyll
off so raw files are served. Without it Jekyll renders `README.md` as the
homepage and your dashboard is buried at `/static/index.html`.

- Source: deploy from a branch, **root** folder
- The root `index.html` forwards to `static/index.html`, preserving the query
  string so `?api=` survives the hop

Your two URLs then look like:

```
https://<user>.github.io/Dark_Web/                     dashboard (static)
https://<render-host>.onrender.com/api/health          backend
```

**CORS.** Render and `github.io` are different origins, but `main.py` registers
`CORSMiddleware` with `allow_origins=["*"]`, so the cross-origin `GET`s and the
JSON `POST` are permitted and option B needs no proxy. That wildcard is fine for
a read-only demo on a synthetic corpus; if you ever expose this with real data or
authentication, pin it to your actual Pages origin instead of `*`.

### Other hosts

| Host | Command |
| --- | --- |
| Railway / Fly / Heroku | `Procfile` is provided; uses `${PORT:-8000}` |
| Docker | `HOST=0.0.0.0 PORT=8000 python main.py` also works, since `main.py` reads `HOST`/`PORT` |
| Local network demo | `python main.py`, then share your LAN IP:8000 |

---

## Tests

```bash
python smoke_test.py                       # boots a temp server, runs 80 checks
python smoke_test.py --base http://127.0.0.1:8000   # test a running server
```

Covers every endpoint, the filter matrix, input validation, all export formats,
the seeded ground truth, and a concurrency section — FastAPI runs these synchronous
endpoints in a threadpool, so the suite hammers the database-backed routes in
parallel to catch unsafe shared state.

---

## Layout

```
main.py         FastAPI app, request models, endpoint layer
engine.py       SQLite schema, NetworkX graph, stylometry, circadian,
                attribution, cluster resolution, exports
seed_data.py    The synthetic corpus (venues, personas, selectors, evidence)
smoke_test.py   End-to-end regression suite
configure_api_base.py  Set the dashboard's API base for a split deploy
static/
  index.html    Single-page dashboard (Tailwind + Cytoscape + Chart.js + Lucide)
index.html      Root forwarding page for GitHub Pages (keeps static/ canonical)
render.yaml     Render blueprint (free-tier deploy)
Procfile        Start command for Railway / Fly / Heroku
.python-version Pins the interpreter for Render
.nojekyll       Switches Jekyll off so GitHub Pages serves the raw files
```

`static/index.html` is the only copy of the dashboard — `main.py` serves it at
`/` and `/static/`, and the root `index.html` merely forwards to it.

The dashboard loads Tailwind, Cytoscape.js, Chart.js and Lucide from a CDN, so the
browser view needs internet on first paint. The API is fully offline.

---

## Limitations

- Attribution quality is bounded by a 141-post synthetic corpus. Real darknet
  language is noisier, and stylometry degrades sharply on short samples — the UI
  reports `INCONCLUSIVE` rather than guessing.
- Currency-transaction clustering uses seeded co-spending labels, not a real
  blockchain graph walk.
- The mh3 favicon hash and certificate artefacts are seeded, not scraped.
- Single-process, in-memory by default. The engine serialises database access
  with a re-entrant lock, which is correct but not a substitute for a real
  connection pool under heavy load.
