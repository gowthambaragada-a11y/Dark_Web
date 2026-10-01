# ANVAYA — Dark Web Threat Actor De-anonymization Platform

**Team Anvaya · Smart India Hackathon 2026 · Problem Statement 26151**

### Live instances

| | Instance | URL |
| --- | --- | --- |
| Dashboard | GitHub Pages | [gowthambaragada-a11y.github.io/Dark_Web](https://gowthambaragada-a11y.github.io/Dark_Web/) |
| API | Render | [dark-web-kts9.onrender.com](https://dark-web-kts9.onrender.com/) |
| Health | Render | [dark-web-kts9.onrender.com/api/health](https://dark-web-kts9.onrender.com/api/health) |

The dashboard also runs standalone at
`https://dark-web-kts9.onrender.com/`, because `main.py` serves it at `/`.

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

The corpus is materialised in-memory on boot, so there is no database to provision
and no migration step. Measured on a clean Python 3.13 install:

| Stage | Cost |
| --- | --- |
| `seed_data.build_database()` | ~0.02 s |
| Corpus + graph + cluster resolution | ~0.05 s |
| Stylometry vectoriser fit + impostor calibration | ~6 s |
| **Total, import to first request** | **~4–8 s** |

Most of that is scikit-learn and scipy import plus fitting the TF-IDF vectorisers,
not the corpus itself. Once warm, `GET /api/actors` is ~36 ms and a full
attribution `POST /api/analyze-persona` is ~140 ms.

To persist the corpus to disk instead:

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

`git push` is the only deploy command. Three GitHub Actions workflows do the rest:

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `pages.yml` | push to `main` | Builds the dashboard and publishes it to GitHub Pages |
| `render-deploy.yml` | push to `main` | Triggers a redeploy of the API on Render |
| `render-bootstrap.yml` | manual, **once** | Creates the Render service through the Render API |

GitHub Pages serves static files only, so it cannot run the FastAPI backend. The
split is therefore deliberate:

- **GitHub Pages** publishes the dashboard at
  [gowthambaragada-a11y.github.io/Dark_Web](https://gowthambaragada-a11y.github.io/Dark_Web/)
- **Render** runs the API, and the Pages build bakes its origin into the page

---

### One-time setup

**1. Point Pages at Actions.** Repo **Settings → Pages → Build and deployment →
Source → GitHub Actions**. Nothing else is needed for the dashboard.

**2. Create the Render service.** Actions tab → **Bootstrap Render service** →
*Run workflow*. Add these first, under **Settings → Secrets and variables →
Actions**:

| Kind | Name | Value |
| --- | --- | --- |
| Secret | `RENDER_API_KEY` | from [render.com/account/api](https://render.com/account/api) |
| Secret | `RENDER_OWNER_ID` | your workspace id (from `GET https://api.render.com/v1/owners`) |

The workflow creates the service with the right start command, region, plan and
health check, and prints its hostname. It is safe to re-run — it adopts an
existing service instead of creating a duplicate.

**3. Wire up the two follow-ups** the bootstrap summary tells you about:

| Kind | Name | Value |
| --- | --- | --- |
| Secret | `RENDER_DEPLOY_HOOK` | Render dashboard → your service → Settings → Deploy Hook |
| Variable | `ANVAYA_API_BASE` | `https://anvaya-deanon.onrender.com` |

`RENDER_DEPLOY_HOOK` is what makes `render-deploy.yml` work — without it that job
skips itself instead of failing, so a fork still gets a green Actions tab.

`ANVAYA_API_BASE` is a repository *variable*, not a secret: it is a public
hostname. The Pages build writes it into `DEFAULT_API_BASE` at build time, so the
dashboard knows where the API is without any code change.

From then on:

```bash
git push
```

...redeploys the API and republishes Pages.

### What the Pages build publishes

Only `index.html`, `static/` and an empty `.nojekyll`. The backend, the corpus
and the test suite are never uploaded to the public bucket. The build fails if
the staged dashboard is missing its API helper or the below-floor footnote.

### Free-tier behaviour

- **Cold starts dominate the demo experience.** Free instances idle out after
  ~15 minutes, then take ~30 s for Render to schedule an instance on top of the
  ~4–8 s this app needs to import and build its vectorisers. Budget roughly
  **30–60 s for the first request after an idle period**; warm requests after
  that are milliseconds. Nothing is provisioned or migrated — but do not demo
  this live right after a long pause.
- **Health check.** Render polls `/api/health`; it reports corpus size, graph
  dimensions and the storage mode, so it doubles as a smoke test.
- **Memory.** Measured peak is 191 MB against the free plan's 512 MB, so there
  is ~320 MB of headroom even under concurrent load.
- **The blueprint is schema-valid.** `render.yaml` validates against Render's
  published JSON schema, and `requirements.txt` installs cleanly on a cold
  Python 3.13.5 venv. The bootstrap workflow uses the same values.
- **One worker, on purpose.** The corpus is materialised in-memory per process.
  A single worker keeps the SQLite state and the lock that guards it coherent.
- **CDN assets.** Tailwind, Cytoscape.js, Chart.js and Lucide load from public
  CDNs, so the *browser* needs internet on first paint. The API never makes an
  outbound request.

### Running it without CI

| Host | Command |
| --- | --- |
| Local | `python main.py`, then open `http://127.0.0.1:8000` |
| LAN demo | `python main.py`, then share your LAN IP:8000 |
| Railway / Fly / Heroku | `Procfile` is provided; uses `${PORT:-8000}` |
| Docker | `HOST=0.0.0.0 PORT=8000 python main.py`, since `main.py` reads `HOST`/`PORT` |

To retarget a local copy of the dashboard at a different backend without
rebuilding:

```bash
python configure_api_base.py --check
python configure_api_base.py https://your-host.onrender.com --verify
python configure_api_base.py --reset      # back to same-origin
```

`?api=<url>` on the dashboard URL overrides it per-request, and
`window.ANVAYA_API_BASE` overrides it per-page.

---

## Tests

```bash
python smoke_test.py                       # boots a temp server, runs 84 checks
python smoke_test.py --base http://127.0.0.1:8000   # test a running server
```

Covers every endpoint, the filter matrix, input validation, all export formats,
the seeded ground truth, a concurrency section — FastAPI runs these synchronous
endpoints in a threadpool, so the suite hammers the database-backed routes in
parallel to catch unsafe shared state — and a latency budget so a performance
regression fails here instead of in front of a judge.

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
