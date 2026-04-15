"""
WatchTower - AI-Powered Threat Intelligence Platform
Version: 1.0.0

Streamlit dashboard that reads real scan findings from BigQuery.
Run with: streamlit run watchtower-dash/app.py
"""

import streamlit as st
import pandas as pd
from datetime import datetime
import json
import os
import sys

# Add parent directory to path so we can import project modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import tempfile
from parse_deps import parse_file
from osv_client import query_osv, extract_cve_ids, summarise_vulns
from epss_client import get_epss_scores
from kev_client import download_kev, check_kev
from scorer import calculate_priority
from llm_client import explain_vulnerability
from bq_client import save_findings
from discord_alert import send_alerts

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================

st.set_page_config(
    page_title="WatchTower | Threat Intelligence Platform",
    page_icon="🗼",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# PROFESSIONAL STYLING
# ============================================================================

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    .stApp {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        color: #e2e8f0;
    }
    
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
        border-right: 1px solid #334155;
        padding-top: 1rem;
    }
    
    [data-testid="stSidebar"] * { color: #cbd5e1; }
    [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 { color: #f1f5f9; }
    
    h1 { color: #f8fafc; font-weight: 600; font-size: 2rem; letter-spacing: -0.025em; }
    h2 { color: #f1f5f9; font-weight: 600; font-size: 1.5rem; margin-top: 2rem; }
    h3 { color: #e2e8f0; font-weight: 600; font-size: 1.125rem; }
    p { color: #cbd5e1; line-height: 1.6; }
    
    [data-testid="stMetricValue"] { color: #f8fafc; font-size: 2.25rem; font-weight: 700; }
    [data-testid="stMetricLabel"] { color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }
    
    .stButton button {
        background-color: transparent;
        border: 1px solid #475569;
        color: #e2e8f0;
        border-radius: 6px;
        padding: 0.5rem 1.25rem;
        font-weight: 500;
        transition: all 0.2s ease;
    }
    .stButton button:hover { background-color: #334155; border-color: #64748b; }
    .stButton button[kind="primary"] { background-color: #059669; border-color: #059669; color: #ffffff; }
    
    hr { border: none; border-top: 1px solid #334155; margin: 1.5rem 0; }
    .block-container { padding-top: 2rem; padding-bottom: 2rem; max-width: 1400px; }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# CONFIGURATION
# ============================================================================

@st.cache_data
def load_stack_config():
    """Load the stack configuration from JSON file."""
    config_paths = ['stack_config.json', 'watchtower-dash/stack_config.json']
    for path in config_paths:
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            continue
    return {
        "company_name": "CloudCart SaaS Platform",
        "backend": "Flask 2.3",
        "database": "PostgreSQL 15",
        "deployment": "Docker Containers",
        "cloud_provider": "Google Cloud Platform",
        "critical_assets": ["Customer Database", "Payment API", "Admin Panel"]
    }

stack_info = load_stack_config()

# ============================================================================
# DATA LOADING — reads from BigQuery
# ============================================================================

@st.cache_data(ttl=60)
def load_scan_data():
    """
    Load the latest scan results from BigQuery.
    Falls back to empty state if BigQuery is unavailable.
    """
    try:
        from bq_client import get_latest_scan, get_all_scans
        findings = get_latest_scan()
        scans = get_all_scans()
        return findings, scans, True
    except Exception as e:
        st.warning(f"Could not load data from BigQuery: {e}")
        return [], [], False


findings, scan_history, bq_connected = load_scan_data()

# Calculate metrics from real data
if findings:
    priority_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        p = f.get("priority", "LOW")
        if p in priority_counts:
            priority_counts[p] += 1

    ACTIVE_THREATS = len(findings)
    CRITICAL_COUNT = priority_counts["CRITICAL"]
    HIGH_COUNT = priority_counts["HIGH"]
    MEDIUM_COUNT = priority_counts["MEDIUM"]
    LOW_COUNT = priority_counts["LOW"]
    TRIAGE_TIME = findings[0].get("triage_time_seconds", 0) if findings else 0
    TOTAL_SCANS = len(scan_history)

    # Extract scan info for sidebar
    SOURCE_FILE = findings[0].get("source_file", "Unknown") if findings else "No scan yet"
    SCAN_TIME = findings[0].get("scan_timestamp", "") if findings else ""
    # Get unique packages scanned
    PACKAGES_SCANNED = list(dict.fromkeys(f.get("package", "") for f in findings))
else:
    ACTIVE_THREATS = 0
    CRITICAL_COUNT = 0
    HIGH_COUNT = 0
    MEDIUM_COUNT = 0
    LOW_COUNT = 0
    TRIAGE_TIME = 0
    TOTAL_SCANS = 0
    SOURCE_FILE = "No scan yet"
    SCAN_TIME = ""
    PACKAGES_SCANNED = []

# ============================================================================
# SIDEBAR
# ============================================================================

with st.sidebar:
    st.markdown("""
        <div style='text-align: center; padding: 1rem 0 2rem 0;'>
            <div style='font-size: 2.5rem; margin-bottom: 0.75rem;'>🗼</div>
            <h1 style='margin: 0; font-size: 1.5rem; font-weight: 700; color: #3b82f6; letter-spacing: 0.1em;'>
                WATCHTOWER
            </h1>
            <p style='margin: 0.5rem 0 0 0; color: #64748b; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.15em; font-weight: 500;'>
                Threat Intelligence Platform
            </p>
        </div>
    """, unsafe_allow_html=True)
    
    st.divider()
    
    # Last scan info
    st.subheader("🎯 Last Scan")
    
    source_display = os.path.basename(SOURCE_FILE) if SOURCE_FILE != "No scan yet" else "No scan yet"
    
    st.markdown(f"""
        <div style='background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%); padding: 1rem; border-radius: 6px; border: 1px solid #2563eb; margin-bottom: 1rem;'>
            <p style='margin: 0; font-size: 0.7rem; color: #93c5fd; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;'>SCANNED FILE</p>
            <p style='margin: 0.5rem 0 0 0; font-size: 1rem; color: #ffffff; font-weight: 600;'>{source_display}</p>
        </div>
    """, unsafe_allow_html=True)
    
    st.divider()
    
    # Dependencies list
    if PACKAGES_SCANNED:
        st.subheader(f"📦 Dependencies ({len(PACKAGES_SCANNED)})")
        
        for pkg in PACKAGES_SCANNED:
            st.markdown(f"""
                <div style='background-color: rgba(30, 41, 59, 0.5); padding: 0.5rem 0.75rem; margin-bottom: 0.25rem; border-radius: 4px; border-left: 3px solid #475569;'>
                    <p style='margin: 0; color: #e2e8f0; font-size: 0.8rem;'>• {pkg}</p>
                </div>
            """, unsafe_allow_html=True)
        
        st.divider()
    
    # Scan results summary
    if findings:
        st.subheader("🔍 Scan Results")
        
        priority_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#f59e0b",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6"
        }
        
        for level, count in [("CRITICAL", CRITICAL_COUNT), ("HIGH", HIGH_COUNT), ("MEDIUM", MEDIUM_COUNT), ("LOW", LOW_COUNT)]:
            color = priority_colors[level]
            st.markdown(f"""
                <div style='background-color: rgba(30, 41, 59, 0.5); padding: 0.5rem 0.75rem; margin-bottom: 0.25rem; border-radius: 4px; border-left: 3px solid {color};'>
                    <p style='margin: 0; color: #e2e8f0; font-size: 0.8rem;'>
                        <span style='color: {color}; font-weight: 700;'>{count}</span> {level}
                    </p>
                </div>
            """, unsafe_allow_html=True)
        
        st.divider()
    
    # Connection status
    status_color = "#059669" if bq_connected else "#dc2626"
    status_text = "CONNECTED TO BIGQUERY" if bq_connected else "BIGQUERY UNAVAILABLE"
    
    st.markdown(f"""
        <div style='background-color: rgba(5, 150, 105, 0.1); padding: 0.75rem; border-radius: 6px; border: 1px solid {status_color};'>
            <p style='margin: 0; color: #6ee7b7; font-size: 0.75rem; font-weight: 600;'>● {status_text}</p>
            <p style='margin: 0.25rem 0 0 0; color: #94a3b8; font-size: 0.7rem;'>Last refresh: {datetime.now().strftime('%H:%M:%S')}</p>
        </div>
    """, unsafe_allow_html=True)
    
    st.divider()
    
    if st.button("🔄 Re-scan for new threats", use_container_width=True):
        st.session_state["rescan_triggered"] = True
        st.cache_data.clear()
        st.rerun()
    
    st.divider()
    st.caption("WatchTower v1.0.0")

# Handle rescan if triggered
if st.session_state.get("rescan_triggered", False):
    st.session_state["rescan_triggered"] = False
    
    try:
        from bq_client import get_last_scan_packages
        packages = get_last_scan_packages()
        
        if packages:
            import time
            
            st.info(f"Re-scanning {len(packages)} packages for new vulnerabilities...")
            start_time = time.time()
            progress = st.progress(0, text="Loading CISA KEV catalogue...")
            
            # Load KEV
            kev_data = download_kev(force=True)  # Force fresh download
            progress.progress(15, text="Scanning against OSV...")
            
            # Query OSV for each package
            all_findings = []
            for i, dep in enumerate(packages):
                pct = 15 + int((i / len(packages)) * 45)
                progress.progress(pct, text=f"Scanning {dep['name']} {dep['version']}...")
                
                vulns = query_osv(dep["name"], dep["version"], dep["ecosystem"])
                if vulns:
                    summaries = summarise_vulns(vulns)
                    for vuln_summary in summaries:
                        finding = {
                            "package": f"{dep['name']} {dep['version']}",
                            "ecosystem": dep["ecosystem"],
                            "vuln_id": vuln_summary["id"],
                            "cve_ids": [a for a in vuln_summary["aliases"] if a.startswith("CVE-")],
                            "summary": vuln_summary["summary"],
                            "severity": vuln_summary["severity"],
                            "epss": None,
                            "epss_percentile": None,
                            "in_kev": False,
                            "kev_details": None,
                        }
                        all_findings.append(finding)
            
            if all_findings:
                # Deduplicate
                progress.progress(65, text="Deduplicating...")
                seen = {}
                for finding in all_findings:
                    key = finding["cve_ids"][0] if finding["cve_ids"] else finding["vuln_id"]
                    if key not in seen:
                        seen[key] = finding
                    else:
                        existing = seen[key]
                        if existing["summary"] == "No summary available" and finding["summary"] != "No summary available":
                            seen[key] = finding
                all_findings = list(seen.values())
                
                # Enrich with EPSS
                progress.progress(70, text="Checking EPSS scores...")
                all_cve_ids = set()
                for f in all_findings:
                    all_cve_ids.update(f["cve_ids"])
                
                epss_scores = {}
                if all_cve_ids:
                    cve_list = list(all_cve_ids)
                    for i in range(0, len(cve_list), 30):
                        chunk = cve_list[i:i + 30]
                        scores = get_epss_scores(chunk)
                        epss_scores.update(scores)
                
                progress.progress(80, text="Checking CISA KEV...")
                kev_matches = check_kev(list(all_cve_ids), kev_data)
                
                for finding in all_findings:
                    for cve_id in finding["cve_ids"]:
                        if cve_id in epss_scores:
                            finding["epss"] = epss_scores[cve_id]["epss"]
                            finding["epss_percentile"] = epss_scores[cve_id]["percentile"]
                        if cve_id in kev_matches:
                            finding["in_kev"] = True
                            finding["kev_details"] = kev_matches[cve_id]
                
                # Score
                for finding in all_findings:
                    score_result = calculate_priority(finding)
                    finding["priority"] = score_result["priority"]
                    finding["priority_rank"] = score_result["priority_rank"]
                    finding["cvss_score"] = score_result["cvss_score"]
                    finding["priority_reasoning"] = score_result["reasoning"]
                
                all_findings.sort(key=lambda f: (f["priority_rank"], -(f["epss"] or 0)))
                
                # LLM for critical/high
                critical_high = [f for f in all_findings if f["priority"] in ("CRITICAL", "HIGH")]
                if critical_high:
                    progress.progress(85, text="Generating AI explanations...")
                    for finding in critical_high:
                        primary_cve = finding["cve_ids"][0] if finding["cve_ids"] else finding["vuln_id"]
                        llm_input = {
                            "package": finding["package"],
                            "vuln_id": primary_cve,
                            "summary": finding["summary"],
                            "priority": finding["priority"],
                            "priority_reasoning": finding["priority_reasoning"],
                            "cvss_score": finding["cvss_score"],
                            "epss": finding["epss"],
                            "epss_percentile": finding["epss_percentile"],
                            "in_kev": finding["in_kev"],
                            "kev_details": finding["kev_details"],
                        }
                        explanation = explain_vulnerability(llm_input)
                        finding["llm_explanation"] = explanation
                
                elapsed = time.time() - start_time
                
                # Send Discord alerts
                send_alerts(all_findings, {
                    "filepath": "rescan",
                    "deps_scanned": len(packages),
                    "elapsed": elapsed,
                })
                
                # Save to BigQuery
                progress.progress(95, text="Saving to BigQuery...")
                try:
                    save_findings(all_findings, "rescan", elapsed)
                except Exception as e:
                    st.warning(f"BigQuery save failed: {e}")
                
                progress.progress(100, text="Re-scan complete!")
                st.cache_data.clear()
                st.rerun()
            else:
                progress.progress(100, text="Re-scan complete — no vulnerabilities found!")
        else:
            st.warning("No previous scan found to re-scan.")
    except Exception as e:
        st.error(f"Re-scan failed: {e}")

# ============================================================================
# MAIN CONTENT
# ============================================================================

st.markdown("""
    <div style='margin-bottom: 2rem;'>
        <h1 style='margin: 0; color: #f8fafc;'>Threat Intelligence Dashboard</h1>
        <p style='margin: 0.5rem 0 0 0; color: #64748b; font-size: 1rem;'>
            Real-time AI-powered threat detection and contextual analysis
        </p>
    </div>
""", unsafe_allow_html=True)

# ============================================================================
# FILE UPLOAD & SCAN
# ============================================================================

def run_scan_pipeline(filepath, filename):
    """Run the full Watchtower scan pipeline and return results."""
    import time

    start_time = time.time()
    progress = st.progress(0, text="Parsing dependencies...")

    # Step 1: Parse
    deps = parse_file(filepath)
    if not deps:
        st.error(f"⚠️ No dependencies found in {filename}. Please upload a valid requirements.txt or package.json file.")
        import time
        time.sleep(2)
        return

    progress.progress(10, text=f"Found {len(deps)} dependencies. Loading CISA KEV...")

    # Step 2: Load KEV
    kev_data = download_kev()
    progress.progress(20, text="Scanning against OSV...")

    # Step 3: Query OSV
    all_findings = []
    for i, dep in enumerate(deps):
        pct = 20 + int((i / len(deps)) * 40)
        progress.progress(pct, text=f"Scanning {dep['name']} {dep['version']}...")

        vulns = query_osv(dep["name"], dep["version"], dep["ecosystem"])
        if vulns:
            summaries = summarise_vulns(vulns)
            for vuln_summary in summaries:
                finding = {
                    "package": f"{dep['name']} {dep['version']}",
                    "ecosystem": dep["ecosystem"],
                    "vuln_id": vuln_summary["id"],
                    "cve_ids": [a for a in vuln_summary["aliases"] if a.startswith("CVE-")],
                    "summary": vuln_summary["summary"],
                    "severity": vuln_summary["severity"],
                    "epss": None,
                    "epss_percentile": None,
                    "in_kev": False,
                    "kev_details": None,
                }
                all_findings.append(finding)

    if not all_findings:
        progress.progress(100, text="Scan complete!")
        st.success(f"✅ No vulnerabilities found in {len(deps)} dependencies. Your stack looks clean!")
        import time
        time.sleep(2)
        return

    # Step 4: Deduplicate
    progress.progress(65, text="Deduplicating findings...")
    seen = {}
    for finding in all_findings:
        key = finding["cve_ids"][0] if finding["cve_ids"] else finding["vuln_id"]
        if key not in seen:
            seen[key] = finding
        else:
            existing = seen[key]
            if existing["summary"] == "No summary available" and finding["summary"] != "No summary available":
                seen[key] = finding
            elif not existing["severity"] and finding["severity"]:
                seen[key] = finding
    all_findings = list(seen.values())

    # Step 5: Enrich
    progress.progress(70, text="Enriching with EPSS scores...")

    all_cve_ids = set()
    for f in all_findings:
        all_cve_ids.update(f["cve_ids"])

    epss_scores = {}
    if all_cve_ids:
        cve_list = list(all_cve_ids)
        for i in range(0, len(cve_list), 30):
            chunk = cve_list[i:i + 30]
            scores = get_epss_scores(chunk)
            epss_scores.update(scores)

    progress.progress(80, text="Checking CISA KEV catalogue...")
    kev_matches = check_kev(list(all_cve_ids), kev_data)

    for finding in all_findings:
        for cve_id in finding["cve_ids"]:
            if cve_id in epss_scores:
                finding["epss"] = epss_scores[cve_id]["epss"]
                finding["epss_percentile"] = epss_scores[cve_id]["percentile"]
            if cve_id in kev_matches:
                finding["in_kev"] = True
                finding["kev_details"] = kev_matches[cve_id]

    # Score
    for finding in all_findings:
        score_result = calculate_priority(finding)
        finding["priority"] = score_result["priority"]
        finding["priority_rank"] = score_result["priority_rank"]
        finding["cvss_score"] = score_result["cvss_score"]
        finding["priority_reasoning"] = score_result["reasoning"]

    all_findings.sort(key=lambda f: (f["priority_rank"], -(f["epss"] or 0)))

    # Step 6: LLM for critical/high
    critical_high = [f for f in all_findings if f["priority"] in ("CRITICAL", "HIGH")]
    if critical_high:
        progress.progress(85, text="Generating AI explanations for critical findings...")
        for finding in critical_high:
            primary_cve = finding["cve_ids"][0] if finding["cve_ids"] else finding["vuln_id"]
            llm_input = {
                "package": finding["package"],
                "vuln_id": primary_cve,
                "summary": finding["summary"],
                "priority": finding["priority"],
                "priority_reasoning": finding["priority_reasoning"],
                "cvss_score": finding["cvss_score"],
                "epss": finding["epss"],
                "epss_percentile": finding["epss_percentile"],
                "in_kev": finding["in_kev"],
                "kev_details": finding["kev_details"],
            }
            explanation = explain_vulnerability(llm_input)
            finding["llm_explanation"] = explanation

    elapsed = time.time() - start_time

    # Send Discord alerts
    send_alerts(all_findings, {
        "filepath": filename,
        "deps_scanned": len(deps),
        "elapsed": elapsed,
    })

    # Save to BigQuery
    progress.progress(95, text="Saving results to BigQuery...")
    try:
        save_findings(all_findings, filename, elapsed)
    except Exception as e:
        st.warning(f"BigQuery save failed: {e}")

    progress.progress(100, text="Scan complete!")

    # Clear cached data so dashboard refreshes
    st.cache_data.clear()


# Upload section
st.markdown("""
    <div style='background: linear-gradient(135deg, #1e3a8a 0%, #1e293b 100%); padding: 1.5rem; border-radius: 8px; border: 1px solid #2563eb; margin-bottom: 2rem;'>
        <h3 style='margin: 0 0 0.5rem 0; color: #93c5fd;'>📂 Scan Dependencies</h3>
        <p style='margin: 0; color: #64748b; font-size: 0.875rem;'>Upload a requirements.txt or package.json to scan for vulnerabilities</p>
    </div>
""", unsafe_allow_html=True)

col_upload, col_scan = st.columns([3, 1])

with col_upload:
    uploaded_file = st.file_uploader(
        "Drop your dependency file here",
        type=["txt", "json"],
        label_visibility="collapsed"
    )

with col_scan:
    scan_clicked = st.button("🔍 Scan Now", use_container_width=True, type="primary", disabled=uploaded_file is None)

if scan_clicked and uploaded_file is not None:
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(mode='w', suffix=uploaded_file.name, delete=False) as tmp:
        content = uploaded_file.read().decode('utf-8')
        tmp.write(content)
        tmp_path = tmp.name

    run_scan_pipeline(tmp_path, uploaded_file.name)

    # Clean up temp file
    os.unlink(tmp_path)

    st.rerun()

st.divider()

# Metrics row
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("VULNERABILITIES", ACTIVE_THREATS)
with col2:
    st.metric("CRITICAL", CRITICAL_COUNT, "Immediate action" if CRITICAL_COUNT > 0 else None, delta_color="off")
with col3:
    st.metric("HIGH", HIGH_COUNT, "Review within 24h" if HIGH_COUNT > 0 else None, delta_color="off")
with col4:
    st.metric("MEDIUM", MEDIUM_COUNT)
with col5:
    st.metric("TRIAGE TIME", f"{TRIAGE_TIME:.1f}s", f"~{ACTIVE_THREATS * 5}min manually", delta_color="off")

st.divider()

# ============================================================================
# FINDINGS DISPLAY
# ============================================================================

if not findings:
    st.info("No scan data found. Upload a dependency file above to run your first scan.")
else:
    # Severity colour mapping
    severity_colors = {
        "CRITICAL": {"bg": "#450a0a", "border": "#dc2626", "badge_bg": "#7f1d1d", "badge_text": "#fca5a5"},
        "HIGH":     {"bg": "#431407", "border": "#f59e0b", "badge_bg": "#78350f", "badge_text": "#fcd34d"},
        "MEDIUM":   {"bg": "#422006", "border": "#eab308", "badge_bg": "#713f12", "badge_text": "#fde047"},
        "LOW":      {"bg": "#0c4a6e", "border": "#3b82f6", "badge_bg": "#075985", "badge_text": "#93c5fd"}
    }

    # Section: CRITICAL and HIGH
    critical_high = [f for f in findings if f.get("priority") in ("CRITICAL", "HIGH")]
    medium = [f for f in findings if f.get("priority") == "MEDIUM"]
    low = [f for f in findings if f.get("priority") == "LOW"]

    if critical_high:
        st.markdown(f"""
            <div style='margin: 2rem 0 1.5rem 0; padding-bottom: 0.75rem; border-bottom: 2px solid #dc2626;'>
                <h2 style='margin: 0; display: inline-block;'>Critical & High Priority</h2>
                <span style='color: #fca5a5; font-size: 0.875rem; margin-left: 1.5rem;'>
                    {len(critical_high)} finding(s) requiring immediate attention
                </span>
            </div>
        """, unsafe_allow_html=True)

        for idx, finding in enumerate(critical_high):
            priority = finding.get("priority", "LOW")
            colors = severity_colors.get(priority, severity_colors["LOW"])
            
            cve_id = finding.get("cve_id", "Unknown")
            package = finding.get("package", "Unknown")
            summary = finding.get("summary", "No summary available")
            cvss = finding.get("cvss_score")
            epss = finding.get("epss_score")
            epss_pct = finding.get("epss_percentile")
            in_kev = finding.get("in_kev", False)
            reasoning = finding.get("priority_reasoning", "")
            llm = finding.get("llm_explanation", "")

            with st.container():
                st.markdown(f"""
                    <div style='
                        background: linear-gradient(135deg, {colors['bg']} 0%, #0f172a 100%);
                        border: 1px solid {colors['border']};
                        border-left: 4px solid {colors['border']};
                        border-radius: 8px;
                        padding: 1.5rem;
                        margin-bottom: 0.5rem;
                    '>
                        <h3 style='margin: 0; color: #f1f5f9;'>{package} — {cve_id}</h3>
                        <p style='margin: 0.5rem 0 0 0; color: #94a3b8;'>{summary}</p>
                    </div>
                """, unsafe_allow_html=True)

                col_a, col_b, col_c, col_d = st.columns(4)
                
                with col_a:
                    st.markdown(f"""
                        <span style='background-color: {colors['badge_bg']}; color: {colors['badge_text']}; 
                        padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700;
                        text-transform: uppercase; display: inline-block;'>{priority}</span>
                    """, unsafe_allow_html=True)
                
                with col_b:
                    cvss_str = f"{cvss:.1f}" if cvss else "N/A"
                    st.caption(f"**CVSS:** {cvss_str}")
                
                with col_c:
                    epss_str = f"{epss * 100:.1f}%" if epss else "N/A"
                    st.caption(f"**EPSS:** {epss_str}")
                
                with col_d:
                    kev_str = "⚠️ ACTIVELY EXPLOITED" if in_kev else "Not in KEV"
                    st.caption(f"**KEV:** {kev_str}")

                st.markdown("---")

                # Chain of reasoning
                st.markdown("**🔍 Chain of Reasoning**")
                
                # Build reasoning bullets from data
                bullets = []
                if in_kev:
                    bullets.append("In CISA KEV — confirmed active exploitation")
                    ransomware = finding.get("ransomware_use")
                    if ransomware == "Known":
                        bullets.append("Known ransomware campaign use")
                else:
                    bullets.append("Not in CISA KEV — not confirmed actively exploited")
                
                if cvss is not None:
                    if cvss >= 9.0: label = "critical severity"
                    elif cvss >= 7.0: label = "high severity"
                    elif cvss >= 4.0: label = "medium severity"
                    else: label = "low severity"
                    bullets.append(f"CVSS {cvss:.1f} — {label}")
                
                if epss is not None:
                    if epss >= 0.7: label = "very high probability of exploitation"
                    elif epss >= 0.2: label = "elevated probability of exploitation"
                    else: label = "low probability of exploitation"
                    bullets.append(f"EPSS {epss * 100:.1f}% — {label}")
                
                for bullet in bullets:
                    st.markdown(f"• {bullet}")
                
                if reasoning:
                    st.markdown(f"**→ {reasoning[:200]}**")

                # LLM explanation
                if llm:
                    st.markdown("")
                    st.markdown("**💡 AI Explanation**")
                    st.write(llm)

                st.markdown("<br>", unsafe_allow_html=True)

    # Section: MEDIUM
    if medium:
        st.markdown(f"""
            <div style='margin: 2rem 0 1.5rem 0; padding-bottom: 0.75rem; border-bottom: 2px solid #eab308;'>
                <h2 style='margin: 0; display: inline-block;'>Medium Priority</h2>
                <span style='color: #fde047; font-size: 0.875rem; margin-left: 1.5rem;'>
                    {len(medium)} finding(s)
                </span>
            </div>
        """, unsafe_allow_html=True)

        for finding in medium:
            colors = severity_colors["MEDIUM"]
            cve_id = finding.get("cve_id", "Unknown")
            package = finding.get("package", "Unknown")
            summary = finding.get("summary", "No summary available")
            cvss = finding.get("cvss_score")
            epss = finding.get("epss_score")
            reasoning = finding.get("priority_reasoning", "")

            cvss_str = f"CVSS {cvss:.1f}" if cvss else "CVSS N/A"
            epss_str = f"EPSS {epss * 100:.1f}%" if epss else "EPSS N/A"

            st.markdown(f"""
                <div style='
                    background: linear-gradient(135deg, {colors['bg']} 0%, #0f172a 100%);
                    border: 1px solid {colors['border']};
                    border-left: 4px solid {colors['border']};
                    border-radius: 8px;
                    padding: 1rem 1.5rem;
                    margin-bottom: 0.5rem;
                '>
                    <div style='display: flex; justify-content: space-between; align-items: center;'>
                        <div>
                            <p style='margin: 0; color: #f1f5f9; font-weight: 600;'>{package} — {cve_id}</p>
                            <p style='margin: 0.25rem 0 0 0; color: #94a3b8; font-size: 0.875rem;'>{summary}</p>
                        </div>
                        <div style='text-align: right;'>
                            <p style='margin: 0; color: #fde047; font-size: 0.8rem; font-weight: 600;'>{cvss_str} | {epss_str}</p>
                        </div>
                    </div>
                </div>
            """, unsafe_allow_html=True)

    # Section: LOW
    if low:
        with st.expander(f"Low Priority ({len(low)} findings)", expanded=False):
            for finding in low:
                cve_id = finding.get("cve_id", "Unknown")
                package = finding.get("package", "Unknown")
                summary = finding.get("summary", "No summary available")
                cvss = finding.get("cvss_score")
                epss = finding.get("epss_score")

                cvss_str = f"CVSS {cvss:.1f}" if cvss else "N/A"
                epss_str = f"EPSS {epss * 100:.1f}%" if epss else "N/A"

                st.markdown(f"""
                    <div style='
                        background-color: rgba(15, 23, 42, 0.5);
                        border-left: 3px solid #475569;
                        padding: 0.75rem 1rem;
                        margin-bottom: 0.25rem;
                        border-radius: 4px;
                    '>
                        <p style='margin: 0; color: #e2e8f0; font-size: 0.875rem;'>
                            <strong>{package}</strong> — {cve_id} | {cvss_str} | {epss_str}
                        </p>
                        <p style='margin: 0.25rem 0 0 0; color: #64748b; font-size: 0.8rem;'>{summary}</p>
                    </div>
                """, unsafe_allow_html=True)

# ============================================================================
# FOOTER
# ============================================================================

st.divider()

st.markdown(f"""
    <div style='text-align: center; padding: 1rem 0; color: #64748b;'>
        <p style='margin: 0; font-size: 0.875rem; font-weight: 500;'>WatchTower Security Operations Center</p>
        <p style='margin: 0.5rem 0 0 0; font-size: 0.75rem;'>Dashboard last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        <p style='margin: 0.25rem 0 0 0; font-size: 0.75rem;'>Protecting {stack_info['company_name']} | {'BigQuery connected' if bq_connected else 'BigQuery unavailable'}</p>
    </div>
""", unsafe_allow_html=True)