# Watchtower

AI-powered vulnerability triage tool that scans your dependencies, checks them against multiple threat intelligence sources, and uses an LLM to produce prioritised risk assessments with full reasoning.

## Data Sources

- **OSV** (Google) — precise package-version vulnerability matching
- **EPSS** (FIRST) — exploit prediction probability scores
- **CISA KEV** — confirmed actively exploited vulnerabilities
- **LLM** (via OpenRouter) — contextual risk assessment with chain of reasoning

## Setup

```bash
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env
# Fill in your API keys in .env
```

## Usage

```bash
# Parse a requirements.txt and scan for vulnerabilities
python parse_deps.py samples/requirements.txt

# Query OSV for a single package
python osv_client.py flask 2.3.0 PyPI

# Check EPSS score for a CVE
python epss_client.py CVE-2024-53907

# Check if a CVE is in CISA KEV
python kev_client.py CVE-2024-53907

# Run the full pipeline
python scan.py samples/requirements.txt
```

## Project Structure

```
watchtower/
├── parse_deps.py      # Dependency file parser (requirements.txt, package.json)
├── osv_client.py      # OSV API client
├── epss_client.py     # EPSS API client
├── kev_client.py      # CISA KEV client
├── llm_client.py      # OpenRouter LLM client
├── scan.py            # Main pipeline — ties everything together
├── samples/           # Sample dependency files for testing
│   ├── requirements.txt
│   └── package.json
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```
