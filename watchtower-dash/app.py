"""Watchtower Streamlit dashboard. Reads scan findings from BigQuery."""

import streamlit as st
import os
import sys
import json
import time
import tempfile
from datetime import datetime

# Add parent directory so we can import project modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from parse_deps import parse_file
from kev_client import download_kev
from bq_client import save_findings
from discord_alert import send_alerts
from pipeline import scan_deps, deduplicate, enrich, score_and_sort, add_llm_explanations

# Page config
st.set_page_config(
    page_title="WatchTower | Threat Intelligence",
    page_icon="🗼",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    .stApp {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        color: #e2e8f0;
    }
    
    #MainMenu, footer, header { visibility: hidden; }
    
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
        background-color: transparent; border: 1px solid #475569; color: #e2e8f0;
        border-radius: 6px; padding: 0.5rem 1.25rem; font-weight: 500; transition: all 0.2s ease;
    }
    .stButton button:hover { background-color: #334155; border-color: #64748b; }
    .stButton button[kind="primary"] { background-color: #059669; border-color: #059669; color: #ffffff; }
    
    hr { border: none; border-top: 1px solid #334155; margin: 1.5rem 0; }
    .block-container { padding-top: 2rem; padding-bottom: 2rem; max-width: 1400px; }
</style>
""", unsafe_allow_html=True)


# Stack config
@st.cache_data
def load_stack_config():
    for path in ['stack_config.json', 'watchtower-dash/stack_config.json']:
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            continue
    return {
        "company_name": "CloudCart SaaS Platform",
        "backend": "Flask 2.3", "database": "PostgreSQL 15",
        "deployment": "Docker Containers", "cloud_provider": "Google Cloud Platform",
        "critical_assets": ["Customer Database", "Payment API", "Admin Panel"]
    }

stack_info = load_stack_config()


# Load data from BigQuery
@st.cache_data(ttl=60)
def load_scan_data():
    try:
        from bq_client import get_latest_scan, get_all_scans
        findings = get_latest_scan()
        scans = get_all_scans()
        return findings, scans, True
    except Exception as e:
        st.warning(f"Could not load from BigQuery: {e}")
        return [], [], False

findings, scan_history, bq_connected = load_scan_data()

# Compute metrics
if findings:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        p = f.get("priority", "LOW")
        if p in counts:
            counts[p] += 1

    TOTAL_VULNS = len(findings)
    TRIAGE_TIME = findings[0].get("triage_time_seconds", 0)
    TOTAL_SCANS = len(scan_history)
    SOURCE_FILE = findings[0].get("source_file", "Unknown")
    PACKAGES = list(dict.fromkeys(f.get("package", "") for f in findings))
else:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    TOTAL_VULNS = 0
    TRIAGE_TIME = 0
    TOTAL_SCANS = 0
    SOURCE_FILE = "No scan yet"
    PACKAGES = []


# --- Shared pipeline runner for dashboard (wraps pipeline.py with progress bars) ---

def run_dashboard_scan(deps, filename, kev_force=False):
    """Run the pipeline with Streamlit progress bars. Used by both upload and rescan."""
    start = time.time()
    progress = st.progress(0, text="Parsing dependencies...")

    if not deps:
        st.error(f"No dependencies found in {filename}.")
        return

    progress.progress(10, text=f"{len(deps)} dependencies. Loading KEV...")
    kev_data = download_kev(force=kev_force)
    progress.progress(20, text="Scanning against OSV...")

    # OSV scan with progress
    all_findings = []
    for i, dep in enumerate(deps):
        pct = 20 + int((i / len(deps)) * 40)
        progress.progress(pct, text=f"Scanning {dep['name']} {dep['version']}...")

        from osv_client import query_osv, summarise_vulns
        from pipeline import build_finding
        vulns = query_osv(dep["name"], dep["version"], dep["ecosystem"])
        if vulns:
            for v in summarise_vulns(vulns):
                all_findings.append(build_finding(dep, v))

    if not all_findings:
        progress.progress(100, text="Scan complete!")
        st.success(f"No vulnerabilities found in {len(deps)} dependencies.")
        time.sleep(2)
        return

    progress.progress(65, text="Deduplicating...")
    all_findings = deduplicate(all_findings)

    progress.progress(70, text="Checking EPSS scores...")
    all_findings = enrich(all_findings, kev_data)

    progress.progress(80, text="Scoring...")
    all_findings = score_and_sort(all_findings)

    critical_high = [f for f in all_findings if f["priority"] in ("CRITICAL", "HIGH")]
    if critical_high:
        progress.progress(85, text="Generating AI explanations...")
        all_findings = add_llm_explanations(all_findings)

    elapsed = time.time() - start

    send_alerts(all_findings, {"filepath": filename, "deps_scanned": len(deps), "elapsed": elapsed})

    progress.progress(95, text="Saving to BigQuery...")
    try:
        save_findings(all_findings, filename, elapsed)
    except Exception as e:
        st.warning(f"BigQuery save failed: {e}")

    progress.progress(100, text="Scan complete!")
    st.cache_data.clear()
    st.rerun()


# --- Sidebar ---

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
    st.subheader("🎯 Last Scan")
    
    source_display = os.path.basename(SOURCE_FILE) if SOURCE_FILE != "No scan yet" else "No scan yet"
    st.markdown(f"""
        <div style='background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%); padding: 1rem; border-radius: 6px; border: 1px solid #2563eb; margin-bottom: 1rem;'>
            <p style='margin: 0; font-size: 0.7rem; color: #93c5fd; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;'>SCANNED FILE</p>
            <p style='margin: 0.5rem 0 0 0; font-size: 1rem; color: #ffffff; font-weight: 600;'>{source_display}</p>
        </div>
    """, unsafe_allow_html=True)
    
    st.divider()
    
    if PACKAGES:
        st.subheader(f"📦 Dependencies ({len(PACKAGES)})")
        for pkg in PACKAGES:
            st.markdown(f"""
                <div style='background-color: rgba(30, 41, 59, 0.5); padding: 0.5rem 0.75rem; margin-bottom: 0.25rem; border-radius: 4px; border-left: 3px solid #475569;'>
                    <p style='margin: 0; color: #e2e8f0; font-size: 0.8rem;'>• {pkg}</p>
                </div>
            """, unsafe_allow_html=True)
        st.divider()
    
    if findings:
        st.subheader("🔍 Scan Results")
        priority_colors = {"CRITICAL": "#dc2626", "HIGH": "#f59e0b", "MEDIUM": "#eab308", "LOW": "#3b82f6"}
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            color = priority_colors[level]
            st.markdown(f"""
                <div style='background-color: rgba(30, 41, 59, 0.5); padding: 0.5rem 0.75rem; margin-bottom: 0.25rem; border-radius: 4px; border-left: 3px solid {color};'>
                    <p style='margin: 0; color: #e2e8f0; font-size: 0.8rem;'>
                        <span style='color: {color}; font-weight: 700;'>{counts[level]}</span> {level}
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


# Handle rescan
if st.session_state.get("rescan_triggered", False):
    st.session_state["rescan_triggered"] = False
    try:
        from bq_client import get_last_scan_packages
        packages = get_last_scan_packages()
        if packages:
            st.info(f"Re-scanning {len(packages)} packages...")
            run_dashboard_scan(packages, "rescan", kev_force=True)
        else:
            st.warning("No previous scan found to re-scan.")
    except Exception as e:
        st.error(f"Re-scan failed: {e}")


# Main content
st.markdown("""
    <div style='margin-bottom: 2rem;'>
        <h1 style='margin: 0; color: #f8fafc;'>Threat Intelligence Dashboard</h1>
        <p style='margin: 0.5rem 0 0 0; color: #64748b; font-size: 1rem;'>
            Real-time AI-powered threat detection and contextual analysis
        </p>
    </div>
""", unsafe_allow_html=True)

# File upload + scan
st.markdown("""
    <div style='background: linear-gradient(135deg, #1e3a8a 0%, #1e293b 100%); padding: 1.5rem; border-radius: 8px; border: 1px solid #2563eb; margin-bottom: 2rem;'>
        <h3 style='margin: 0 0 0.5rem 0; color: #93c5fd;'>📂 Scan Dependencies</h3>
        <p style='margin: 0; color: #64748b; font-size: 0.875rem;'>Upload a requirements.txt or package.json to scan for vulnerabilities</p>
    </div>
""", unsafe_allow_html=True)

col_upload, col_scan = st.columns([3, 1])
with col_upload:
    uploaded_file = st.file_uploader("Drop your dependency file here", type=["txt", "json"], label_visibility="collapsed")
with col_scan:
    scan_clicked = st.button("🔍 Scan Now", use_container_width=True, type="primary", disabled=uploaded_file is None)

if scan_clicked and uploaded_file is not None:
    with tempfile.NamedTemporaryFile(mode='w', suffix=uploaded_file.name, delete=False) as tmp:
        tmp.write(uploaded_file.read().decode('utf-8'))
        tmp_path = tmp.name

    deps = parse_file(tmp_path)
    os.unlink(tmp_path)
    run_dashboard_scan(deps, uploaded_file.name)

st.divider()

# Metrics row
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("VULNERABILITIES", TOTAL_VULNS)
col2.metric("CRITICAL", counts["CRITICAL"], "Immediate action" if counts["CRITICAL"] > 0 else None, delta_color="off")
col3.metric("HIGH", counts["HIGH"], "Review within 24h" if counts["HIGH"] > 0 else None, delta_color="off")
col4.metric("MEDIUM", counts["MEDIUM"])
col5.metric("TRIAGE TIME", f"{TRIAGE_TIME:.1f}s", f"~{TOTAL_VULNS * 5}min manually", delta_color="off")

st.divider()

# Findings display
SEVERITY_COLORS = {
    "CRITICAL": {"bg": "#450a0a", "border": "#dc2626", "badge_bg": "#7f1d1d", "badge_text": "#fca5a5"},
    "HIGH":     {"bg": "#431407", "border": "#f59e0b", "badge_bg": "#78350f", "badge_text": "#fcd34d"},
    "MEDIUM":   {"bg": "#422006", "border": "#eab308", "badge_bg": "#713f12", "badge_text": "#fde047"},
    "LOW":      {"bg": "#0c4a6e", "border": "#3b82f6", "badge_bg": "#075985", "badge_text": "#93c5fd"},
}


def render_finding_detail(finding):
    """Render a CRITICAL/HIGH finding with full detail."""
    priority = finding.get("priority", "LOW")
    colors = SEVERITY_COLORS.get(priority, SEVERITY_COLORS["LOW"])
    
    cve_id = finding.get("cve_id", "Unknown")
    package = finding.get("package", "Unknown")
    summary = finding.get("summary", "No summary available")
    cvss = finding.get("cvss_score")
    epss = finding.get("epss_score")
    in_kev = finding.get("in_kev", False)
    reasoning = finding.get("priority_reasoning", "")
    llm = finding.get("llm_explanation", "")

    with st.container():
        st.markdown(f"""
            <div style='
                background: linear-gradient(135deg, {colors['bg']} 0%, #0f172a 100%);
                border: 1px solid {colors['border']}; border-left: 4px solid {colors['border']};
                border-radius: 8px; padding: 1.5rem; margin-bottom: 0.5rem;
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
            st.caption(f"**CVSS:** {f'{cvss:.1f}' if cvss else 'N/A'}")
        with col_c:
            st.caption(f"**EPSS:** {f'{epss * 100:.1f}%' if epss else 'N/A'}")
        with col_d:
            st.caption(f"**KEV:** {'⚠️ ACTIVELY EXPLOITED' if in_kev else 'Not in KEV'}")

        st.markdown("---")
        st.markdown("**🔍 Chain of Reasoning**")
        
        # Reasoning bullets
        if in_kev:
            st.markdown("• In CISA KEV — confirmed active exploitation")
            if finding.get("ransomware_use") == "Known":
                st.markdown("• Known ransomware campaign use")
        else:
            st.markdown("• Not in CISA KEV")
        
        if cvss is not None:
            label = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
            st.markdown(f"• CVSS {cvss:.1f} — {label} severity")
        
        if epss is not None:
            label = "very high" if epss >= 0.7 else "elevated" if epss >= 0.2 else "low"
            st.markdown(f"• EPSS {epss * 100:.1f}% — {label} exploitation probability")
        
        if reasoning:
            st.markdown(f"**→ {reasoning[:200]}**")

        if llm:
            st.markdown("")
            st.markdown("**💡 AI Explanation**")
            st.write(llm)

        st.markdown("<br>", unsafe_allow_html=True)


def render_finding_compact(finding, colors):
    """Render a MEDIUM finding as a compact card."""
    cve_id = finding.get("cve_id", "Unknown")
    package = finding.get("package", "Unknown")
    summary = finding.get("summary", "No summary available")
    cvss = finding.get("cvss_score")
    epss = finding.get("epss_score")

    cvss_str = f"CVSS {cvss:.1f}" if cvss else "CVSS N/A"
    epss_str = f"EPSS {epss * 100:.1f}%" if epss else "EPSS N/A"

    st.markdown(f"""
        <div style='
            background: linear-gradient(135deg, {colors['bg']} 0%, #0f172a 100%);
            border: 1px solid {colors['border']}; border-left: 4px solid {colors['border']};
            border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 0.5rem;
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


if not findings:
    st.info("No scan data found. Upload a dependency file above to run your first scan.")
else:
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
        for f in critical_high:
            render_finding_detail(f)

    if medium:
        st.markdown(f"""
            <div style='margin: 2rem 0 1.5rem 0; padding-bottom: 0.75rem; border-bottom: 2px solid #eab308;'>
                <h2 style='margin: 0; display: inline-block;'>Medium Priority</h2>
                <span style='color: #fde047; font-size: 0.875rem; margin-left: 1.5rem;'>{len(medium)} finding(s)</span>
            </div>
        """, unsafe_allow_html=True)
        for f in medium:
            render_finding_compact(f, SEVERITY_COLORS["MEDIUM"])

    if low:
        with st.expander(f"Low Priority ({len(low)} findings)", expanded=False):
            for f in low:
                cve_id = f.get("cve_id", "Unknown")
                package = f.get("package", "Unknown")
                summary = f.get("summary", "No summary available")
                cvss = f.get("cvss_score")
                epss = f.get("epss_score")

                cvss_str = f"CVSS {cvss:.1f}" if cvss else "N/A"
                epss_str = f"EPSS {epss * 100:.1f}%" if epss else "N/A"

                st.markdown(f"""
                    <div style='
                        background-color: rgba(15, 23, 42, 0.5); border-left: 3px solid #475569;
                        padding: 0.75rem 1rem; margin-bottom: 0.25rem; border-radius: 4px;
                    '>
                        <p style='margin: 0; color: #e2e8f0; font-size: 0.875rem;'>
                            <strong>{package}</strong> — {cve_id} | {cvss_str} | {epss_str}
                        </p>
                        <p style='margin: 0.25rem 0 0 0; color: #64748b; font-size: 0.8rem;'>{summary}</p>
                    </div>
                """, unsafe_allow_html=True)

# Footer
st.divider()
st.markdown(f"""
    <div style='text-align: center; padding: 1rem 0; color: #64748b;'>
        <p style='margin: 0; font-size: 0.875rem; font-weight: 500;'>WatchTower Security Operations Center</p>
        <p style='margin: 0.5rem 0 0 0; font-size: 0.75rem;'>Dashboard last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        <p style='margin: 0.25rem 0 0 0; font-size: 0.75rem;'>Protecting {stack_info['company_name']} | {'BigQuery connected' if bq_connected else 'BigQuery unavailable'}</p>
    </div>
""", unsafe_allow_html=True)