# Vulnerability Prioritization Scorer

A Streamlit-based tool for security teams to enrich raw CVE lists with live NVD and EPSS data, then rank vulnerabilities using a configurable multi-factor composite scoring formula. Designed to cut through alert fatigue and surface the vulnerabilities that genuinely need patching first.

---

## Features

- Upload any CSV of CVE IDs (with optional asset name and exposure tier)
- Live enrichment from NVD API v2 (CVSS v3, published date) and FIRST EPSS API (exploit probability)
- Composite scoring: CVSS severity + exploit probability + asset exposure + age decay
- Fully adjustable weights and exposure tier values via sidebar sliders
- Stacked bar chart showing per-factor score contributions (Top 20 CVEs)
- Priority band breakdown: Critical / High / Medium / Low with count metrics
- Filterable results table with per-band tabs
- Session-cached API responses — tweak weights and re-score without re-fetching
- Export: scored CSV and self-contained HTML report (with embedded Plotly chart)
- Graceful degradation when NVD or EPSS APIs are unavailable

---

## Quick Start

```bash
# 1. Clone the repo
git clone <repo-url>
cd vuln-prioritization-scorer

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Set your NVD API key
cp .env.example .env
# Edit .env and add your key — speeds up NVD fetching from 5 req/30s to 50 req/30s

# 5. Run the app
streamlit run app.py
```

The app will open at `http://localhost:8501`.

---

## CSV Format

The input CSV requires a `cve_id` column. `asset_name` and `asset_exposure` are optional.

```csv
cve_id,asset_name,asset_exposure
CVE-2021-44228,prod-api-gateway-01,internet-facing
CVE-2023-23397,exchange-server-corp,internal
CVE-2022-30190,workstation-fleet,
CVE-2021-34527,print-spooler-srv,internet-facing
CVE-2020-1472,domain-controller-01,critical-infra
```

Valid exposure tiers: `internet-facing`, `critical-infra`, `internal`, `unknown` (default when blank).

A sample file is included at `tests/fixtures/sample_upload.csv`, or click "Load sample data" in the app.

---

## Scoring Formula

```
composite_score = w_cvss * N_cvss + w_epss * N_epss + w_exposure * N_exposure + w_age * N_age
```

### Default Weights

| Factor         | Default Weight | Normalization                                        |
|----------------|---------------|------------------------------------------------------|
| CVSS v3        | 0.35          | `cvss / 10.0`                                        |
| EPSS           | 0.30          | `sqrt(epss_probability)` — square-root stretch        |
| Exposure tier  | 0.20          | Ordinal map (see table below)                        |
| Age decay      | 0.15          | `log1p(age_days) / log1p(365*3)`, capped at 1.0      |

### Exposure Tier Values (adjustable in sidebar)

| Tier             | Default Value |
|------------------|--------------|
| internet-facing  | 1.0          |
| critical-infra   | 0.9          |
| unknown          | 0.6          |
| internal         | 0.5          |

### Priority Bands

| Band     | Score Range    |
|----------|---------------|
| Critical | >= 0.75       |
| High     | >= 0.55       |
| Medium   | >= 0.35       |
| Low      | < 0.35        |

Weights are auto-normalized to sum to 1.0 when adjusted via the sidebar sliders.

---

## NVD API Key Setup

Without a key, NVD rate-limits requests to 5 per 30 seconds (6.5s delay between calls).
With a free API key, the limit rises to 50 per 30 seconds (0.6s delay).

1. Register at https://nvd.nist.gov/developers/request-an-api-key
2. Add to `.env`:
   ```
   NVD_API_KEY=your_key_here
   ```
   Or paste it directly in the sidebar "NVD API Key" field at runtime.

---

## Running Tests

```bash
pytest tests/ -v
```

Tests cover: scoring logic, priority band assignment, age decay normalization, and NVD client with mocked HTTP responses.

---

## Tech Stack

| Component       | Library                  |
|-----------------|--------------------------|
| UI / app server | Streamlit >= 1.32        |
| Data processing | pandas >= 2.0            |
| HTTP clients    | requests >= 2.31         |
| Charting        | Plotly >= 5.18           |
| HTML templating | Jinja2 >= 3.1            |
| Env management  | python-dotenv >= 1.0     |
| Testing         | pytest >= 8.0            |

Data sources:
- **NVD API v2** — https://services.nvd.nist.gov/rest/json/cves/2.0
- **FIRST EPSS API** — https://api.first.org/data/1.0/epss

---

## Project Structure

```
vuln-prioritization-scorer/
├── app.py                    # Streamlit entry point
├── config.py                 # Weights, tiers, API URLs, constants
├── requirements.txt
├── .env.example
├── core/
│   ├── scorer.py             # compute_scores(), assign_priority_band()
│   ├── age_decay.py          # compute_age_days(), normalize_age()
│   └── normalizer.py         # normalize_cvss(), normalize_epss(), normalize_exposure()
├── api/
│   ├── nvd_client.py         # NVDClient with rate limiting
│   ├── epss_client.py        # EPSSClient with chunked batch fetch
│   └── cache.py              # Streamlit session_state cache
├── ui/
│   ├── uploader.py           # CSV upload + validation
│   ├── sidebar.py            # Weight/tier sliders, API key input
│   └── results_table.py      # Metrics, stacked bar chart, tabbed table
├── export/
│   ├── csv_exporter.py       # DataFrame → CSV bytes
│   └── html_report.py        # Jinja2 HTML report with embedded chart
├── templates/
│   └── report.html.j2        # Self-contained HTML report template
└── tests/
    ├── test_scorer.py
    ├── test_age_decay.py
    ├── test_nvd_client.py
    └── fixtures/
        ├── sample_upload.csv
        └── nvd_response_fixture.json
```
