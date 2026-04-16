# Watchtower 🗼

Scans your dependencies against threat intelligence sources and uses an LLM to explain prioritised vulnerabilities.

**[Live Dashboard](https://watchtower-undnaiw3chizm9cnwrurnj.streamlit.app)**

## Data Sources

- **OSV** (Google) for package-version vulnerability matching
- **EPSS** (FIRST) for exploit prediction scores
- **CISA KEV** for confirmed actively exploited CVEs

The LLM never influences scoring. It only generates explanations for CRITICAL and HIGH findings after the fact. Scoring is rules-based, using thresholds from the FIRST.org EPSS User Guide.

## Setup

```bash
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env
```

You'll need three keys in your `.env`:

```
OPENROUTER_API_KEY=
GOOGLE_APPLICATION_CREDENTIALS=
DISCORD_WEBHOOK_URL=
```

Run this once before your first scan to set up BigQuery:

```bash
python bq_client.py
```

## Usage

```bash
# Full scan
python scan.py samples/requirements.txt

# Without LLM explanations
python scan.py samples/requirements.txt --no-llm
```

## Dashboard

```bash
streamlit run watchtower-dash/app.py
```

Or use the [hosted version](https://watchtower-undnaiw3chizm9cnwrurnj.streamlit.app). Supports file upload and scanning from the UI.

## Project Structure

```
watchtower/
├── scan.py                # Entry point
├── pipeline.py            # Core pipeline logic
├── parse_deps.py          # Parses requirements.txt and package.json
├── scorer.py              # Rules-based priority scoring
├── osv_client.py          # OSV API client
├── epss_client.py         # EPSS API client
├── kev_client.py          # CISA KEV client
├── llm_client.py          # OpenRouter explanations
├── bq_client.py           # BigQuery read/write
├── discord_alert.py       # Alerts for CRITICAL/HIGH findings
├── watchtower-dash/
│   └── app.py             # Streamlit dashboard
├── samples/
│   ├── requirements.txt
│   └── package.json
├── .env.example
├── .gitignore
└── requirements.txt
```
