"""
WatchTower - AI-Powered Threat Intelligence Platform
Version: 1.0.0
Author: CloudCart Security Team

This module provides the main Streamlit dashboard interface for the WatchTower
threat intelligence platform. It displays real-time cyber threat data with
AI-powered analysis and severity classification.

Dependencies:
    - streamlit: Web application framework
    - pandas: Data manipulation
    - bigquery_helper: Custom BigQuery integration module (optional)
"""

import streamlit as st
import pandas as pd
from datetime import datetime
import json
import os

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
# Modern, clean cybersecurity aesthetic with proper color theory
# ============================================================================

st.markdown("""
<style>
    /* Import professional font family */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    /* Main application background */
    .stApp {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        color: #e2e8f0;
    }
    
    /* Remove default Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
        border-right: 1px solid #334155;
        padding-top: 1rem;
    }
    
    [data-testid="stSidebar"] * {
        color: #cbd5e1;
    }
    
    [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3 {
        color: #f1f5f9;
    }
    
    /* Typography */
    h1 {
        color: #f8fafc;
        font-weight: 600;
        font-size: 2rem;
        margin-bottom: 0.5rem;
        letter-spacing: -0.025em;
    }
    
    h2 {
        color: #f1f5f9;
        font-weight: 600;
        font-size: 1.5rem;
        margin-top: 2rem;
        margin-bottom: 1rem;
    }
    
    h3 {
        color: #e2e8f0;
        font-weight: 600;
        font-size: 1.125rem;
        margin-bottom: 0.75rem;
    }
    
    p {
        color: #cbd5e1;
        line-height: 1.6;
    }
    
    .stCaption {
        color: #64748b !important;
        font-size: 0.875rem;
    }
    
    /* Metric cards */
    [data-testid="stMetricValue"] {
        color: #f8fafc;
        font-size: 2.25rem;
        font-weight: 700;
        letter-spacing: -0.025em;
    }
    
    [data-testid="stMetricLabel"] {
        color: #94a3b8;
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-weight: 600;
    }
    
    [data-testid="stMetricDelta"] {
        font-size: 0.875rem;
    }
    
    /* Buttons */
    .stButton button {
        background-color: transparent;
        border: 1px solid #475569;
        color: #e2e8f0;
        border-radius: 6px;
        padding: 0.5rem 1.25rem;
        font-weight: 500;
        font-size: 0.875rem;
        transition: all 0.2s ease;
        letter-spacing: 0.025em;
    }
    
    .stButton button:hover {
        background-color: #334155;
        border-color: #64748b;
        transform: translateY(-1px);
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    
    .stButton button[kind="primary"] {
        background-color: #059669;
        border-color: #059669;
        color: #ffffff;
    }
    
    .stButton button[kind="primary"]:hover {
        background-color: #047857;
        border-color: #047857;
    }
    
    /* Dividers */
    hr {
        border: none;
        border-top: 1px solid #334155;
        margin: 1.5rem 0;
    }
    
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 1400px;
    }
    
    /* Alert boxes */
    .stSuccess {
        background-color: rgba(5, 150, 105, 0.1);
        border-left: 4px solid #059669;
        color: #d1fae5;
    }
    
    .stInfo {
        background-color: rgba(30, 64, 175, 0.1);
        border-left: 4px solid #1e40af;
        color: #dbeafe;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# CONFIGURATION LOADING
# ============================================================================

@st.cache_data
def load_stack_config():
    """Load the protected stack configuration from JSON file."""
    try:
        with open('stack_config.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
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
# SIDEBAR
# ============================================================================

with st.sidebar:
    
    # Branding
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
    
    # Protected environment
    st.subheader("🎯 Protected Environment")
    
    st.markdown(f"""
        <div style='background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%); padding: 1rem; border-radius: 6px; border: 1px solid #2563eb; margin-bottom: 1rem;'>
            <p style='margin: 0; font-size: 0.7rem; color: #93c5fd; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;'>
                MONITORED ASSET
            </p>
            <p style='margin: 0.5rem 0 0 0; font-size: 1rem; color: #ffffff; font-weight: 600;'>
                {stack_info['company_name']}
            </p>
        </div>
    """, unsafe_allow_html=True)
    
    # Technology stack
    st.markdown("**Technology Stack**")
    
    stack_components = [
        ("💻", "Backend", stack_info['backend']),
        ("🗄️", "Database", stack_info['database']),
        ("📦", "Deployment", stack_info['deployment']),
        ("☁️", "Cloud", stack_info['cloud_provider'])
    ]
    
    for icon, label, value in stack_components:
        st.markdown(f"""
            <div style='background-color: rgba(30, 41, 59, 0.5); padding: 0.75rem; margin-bottom: 0.5rem; border-radius: 4px; border-left: 3px solid #475569;'>
                <p style='margin: 0; font-size: 0.7rem; color: #94a3b8; text-transform: uppercase;'>{icon} {label}</p>
                <p style='margin: 0.25rem 0 0 0; color: #e2e8f0; font-weight: 500;'>{value}</p>
            </div>
        """, unsafe_allow_html=True)
    
    st.divider()
    
    # Critical assets
    st.subheader("🔐 Critical Assets")
    
    for asset in stack_info['critical_assets']:
        st.markdown(f"""
            <div style='background-color: rgba(220, 38, 38, 0.1); padding: 0.5rem 0.75rem; margin-bottom: 0.5rem; border-radius: 4px; border-left: 3px solid #dc2626;'>
                <p style='margin: 0; color: #fca5a5; font-size: 0.875rem;'>• {asset}</p>
            </div>
        """, unsafe_allow_html=True)
    
    st.divider()
    
    # System status
    current_time = datetime.now().strftime('%H:%M:%S')
    
    st.markdown(f"""
        <div style='background-color: rgba(5, 150, 105, 0.1); padding: 0.75rem; border-radius: 6px; border: 1px solid #059669;'>
            <p style='margin: 0; color: #6ee7b7; font-size: 0.75rem; font-weight: 600;'>● OPERATIONAL</p>
            <p style='margin: 0.25rem 0 0 0; color: #94a3b8; font-size: 0.7rem;'>Last scan: {current_time}</p>
        </div>
    """, unsafe_allow_html=True)
    
    st.divider()
    
    st.caption("WatchTower v1.0.0")
    st.caption("© 2026 CloudCart Security")

# ============================================================================
# DATA LOADING
# ============================================================================

USE_BIGQUERY = os.path.exists('bigquery-key.json')

if USE_BIGQUERY:
    try:
        from bigquery_helper import BigQueryHelper
        bq = BigQueryHelper()
        counts = bq.get_threat_counts()
        resolved_today = bq.get_resolved_today_count()
        threats = bq.get_active_threats(limit=9)
        
        ACTIVE_THREATS = counts['total_active']
        CRITICAL_COUNT = counts['critical_count']
        HIGH_COUNT = counts['high_count']
        RESOLVED_TODAY = resolved_today
        sample_threats = threats
        
    except Exception as e:
        st.error(f"BigQuery connection failed: {e}")
        st.warning("Falling back to demonstration data...")
        USE_BIGQUERY = False

if not USE_BIGQUERY:
    ACTIVE_THREATS = 7
    CRITICAL_COUNT = 2
    HIGH_COUNT = 3
    RESOLVED_TODAY = 12
    
    sample_threats = [
        {
            "threat_id": "CVE-2026-1842",
            "threat_name": "PostgreSQL Remote Code Execution Vulnerability",
            "severity": "critical",
            "source": "NVD Database",
            "detected_at": "2026-04-14 13:42:18",
            "reason": "The protected stack uses PostgreSQL 15 in containerized deployment. This CVE targets exposed PostgreSQL services and allows remote code execution through malformed SQL queries.",
            "recommended_action": "Apply security patch PostgreSQL 15.6 immediately. Review database access logs for suspicious queries. Restart affected containers.",
            "confidence": "high",
            "cvss_score": 9.8
        },
        {
            "threat_id": "CVE-2026-2103",
            "threat_name": "Docker Container Escape via runC Exploit",
            "severity": "critical",
            "source": "GitHub Security Advisory",
            "detected_at": "2026-04-14 11:15:03",
            "reason": "Your Docker deployment is vulnerable to container escape attacks. This exploit allows attackers to break out of containerized environments.",
            "recommended_action": "Update runC to version 1.1.12 or later. Audit all running containers. Enable AppArmor or SELinux profiles.",
            "confidence": "high",
            "cvss_score": 9.3
        },
        {
            "threat_id": "CVE-2026-1756",
            "threat_name": "Flask Session Cookie Forgery Vulnerability",
            "severity": "high",
            "source": "CVE Database",
            "detected_at": "2026-04-14 09:28:41",
            "reason": "Flask backend versions prior to 2.3.5 are susceptible to session cookie forgery attacks, potentially allowing attackers to impersonate authenticated users.",
            "recommended_action": "Upgrade Flask to version 2.3.5. Rotate all session secret keys. Invalidate existing user sessions.",
            "confidence": "high",
            "cvss_score": 8.1
        },
        {
            "threat_id": "EXPLOIT-2026-0891",
            "threat_name": "GCP Cloud Storage Misconfiguration Scanner",
            "severity": "high",
            "source": "Dark Web Intelligence",
            "detected_at": "2026-04-14 08:12:55",
            "reason": "Active exploitation tool detected on underground forums targeting misconfigured Google Cloud Storage buckets.",
            "recommended_action": "Audit all GCP storage bucket permissions immediately. Enable uniform bucket-level access control.",
            "confidence": "medium",
            "cvss_score": 7.5
        },
        {
            "threat_id": "CVE-2026-1923",
            "threat_name": "Python Pickle Deserialization RCE",
            "severity": "high",
            "source": "NVD Database",
            "detected_at": "2026-04-13 22:47:12",
            "reason": "Flask application using pickle for session handling can lead to arbitrary code execution with untrusted pickle data.",
            "recommended_action": "Audit codebase for pickle usage. Replace with JSON serialization. Implement strict input validation.",
            "confidence": "medium",
            "cvss_score": 7.8
        },
        {
            "threat_id": "THREAT-2026-1402",
            "threat_name": "Credential Stuffing Campaign Targeting SaaS Platforms",
            "severity": "medium",
            "source": "Threat Intelligence Feed",
            "detected_at": "2026-04-13 18:33:27",
            "reason": "Large-scale credential stuffing attacks detected against SaaS platforms using leaked credentials from third-party breaches.",
            "recommended_action": "Enable rate limiting on authentication endpoints. Implement CAPTCHA. Force password resets for compromised accounts.",
            "confidence": "medium",
            "cvss_score": 6.5
        },
        {
            "threat_id": "CVE-2026-0847",
            "threat_name": "GCP Metadata Service SSRF Vulnerability",
            "severity": "medium",
            "source": "CVE Database",
            "detected_at": "2026-04-13 14:19:08",
            "reason": "Applications on GCP making server-side HTTP requests may be vulnerable to SSRF attacks targeting the metadata service.",
            "recommended_action": "Review code for user-controlled URLs. Implement URL allowlisting. Deploy VPC Service Controls.",
            "confidence": "low",
            "cvss_score": 5.9
        }
    ]

# ============================================================================
# MAIN CONTENT
# ============================================================================

# Header
st.markdown("""
    <div style='margin-bottom: 2rem;'>
        <h1 style='margin: 0; color: #f8fafc;'>Threat Intelligence Dashboard</h1>
        <p style='margin: 0.5rem 0 0 0; color: #64748b; font-size: 1rem;'>
            Real-time AI-powered threat detection and contextual analysis
        </p>
    </div>
""", unsafe_allow_html=True)

# Metrics
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("ACTIVE THREATS", ACTIVE_THREATS, "-2 from yesterday", delta_color="inverse")

with col2:
    st.metric("CRITICAL", CRITICAL_COUNT, "Immediate action required", delta_color="off")

with col3:
    st.metric("HIGH PRIORITY", HIGH_COUNT, "Review within 24h", delta_color="off")

with col4:
    st.metric("RESOLVED TODAY", RESOLVED_TODAY, f"+{RESOLVED_TODAY - 9} from yesterday", delta_color="normal")

st.divider()

# Section header
st.markdown("""
    <div style='margin: 2rem 0 1.5rem 0; padding-bottom: 0.75rem; border-bottom: 2px solid #334155;'>
        <h2 style='margin: 0; display: inline-block;'>Priority Threat Queue</h2>
        <span style='color: #64748b; font-size: 0.875rem; margin-left: 1.5rem;'>
            Displaying top 9 threats ranked by severity and detection time
        </span>
    </div>
""", unsafe_allow_html=True)

# Threat cards
for idx, threat in enumerate(sample_threats):
    
    severity_colors = {
        "critical": {"bg": "#450a0a", "border": "#dc2626", "badge_bg": "#7f1d1d", "badge_text": "#fca5a5"},
        "high": {"bg": "#431407", "border": "#f59e0b", "badge_bg": "#78350f", "badge_text": "#fcd34d"},
        "medium": {"bg": "#422006", "border": "#eab308", "badge_bg": "#713f12", "badge_text": "#fde047"},
        "low": {"bg": "#0c4a6e", "border": "#3b82f6", "badge_bg": "#075985", "badge_text": "#93c5fd"}
    }
    
    colors = severity_colors.get(threat['severity'], severity_colors["low"])
    
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
                <h3 style='margin: 0; color: #f1f5f9; font-size: 1.125rem;'>{threat['threat_name']}</h3>
            </div>
        """, unsafe_allow_html=True)
        
        col_meta1, col_meta2, col_meta3, col_meta4 = st.columns(4)
        
        with col_meta1:
            st.markdown(f"""
                <span style='
                    background-color: {colors['badge_bg']}; 
                    color: {colors['badge_text']}; 
                    padding: 0.25rem 0.75rem; 
                    border-radius: 4px; 
                    font-size: 0.75rem; 
                    font-weight: 700;
                    text-transform: uppercase;
                    display: inline-block;
                '>
                    {threat['severity'].upper()}
                </span>
            """, unsafe_allow_html=True)
        
        with col_meta2:
            st.caption(f"**ID:** `{threat['threat_id']}`")
        
        with col_meta3:
            st.caption(f"**CVSS:** {threat.get('cvss_score', 'N/A')}")
        
        with col_meta4:
            st.caption(f"**Confidence:** {threat.get('confidence', 'medium').upper()}")
        
        st.caption(f"📡 **Source:** {threat['source']} | 🕒 **Detected:** {threat['detected_at']}")
        
        st.markdown("---")
        
        st.markdown("**⚡ Threat Analysis**")
        st.write(threat['reason'])
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            if st.button("View Recommended Action", key=f"view_{idx}", use_container_width=True):
                st.session_state[f'show_{idx}'] = not st.session_state.get(f'show_{idx}', False)
        
        with col2:
            if st.button("Resolve", key=f"resolve_{idx}", type="primary", use_container_width=True):
                if USE_BIGQUERY:
                    success = bq.update_threat_status(threat['threat_id'], 'resolved')
                    if success:
                        st.success(f"✓ {threat['threat_id']} marked as resolved")
                        st.rerun()
                    else:
                        st.error("Failed to update threat status")
                else:
                    st.success(f"✓ {threat['threat_id']} marked as resolved (demo mode)")
        
        with col3:
            if st.button("Dismiss", key=f"dismiss_{idx}", use_container_width=True):
                if USE_BIGQUERY:
                    success = bq.update_threat_status(threat['threat_id'], 'dismissed')
                    if success:
                        st.info(f"Dismissed {threat['threat_id']}")
                        st.rerun()
                    else:
                        st.error("Failed to update threat status")
                else:
                    st.info(f"Dismissed {threat['threat_id']} (demo mode)")
        
        if st.session_state.get(f'show_{idx}', False):
            st.info(f"**Recommended Response Actions:**\n\n{threat['recommended_action']}")
            
            if st.button("Mark as Handled", key=f"done_{idx}"):
                if USE_BIGQUERY:
                    success = bq.update_threat_status(threat['threat_id'], 'resolved')
                    if success:
                        st.success(f"✓ {threat['threat_id']} resolved and removed from queue")
                        st.session_state[f'show_{idx}'] = False
                        st.rerun()
                    else:
                        st.error("Failed to mark as handled")
                else:
                    st.success(f"✓ {threat['threat_id']} handled (demo mode)")
                    st.session_state[f'show_{idx}'] = False
                    st.rerun()
        
        st.markdown("<br>", unsafe_allow_html=True)

# Footer
st.divider()

st.markdown(f"""
    <div style='text-align: center; padding: 1rem 0; color: #64748b;'>
        <p style='margin: 0; font-size: 0.875rem; font-weight: 500;'>WatchTower Security Operations Center</p>
        <p style='margin: 0.5rem 0 0 0; font-size: 0.75rem;'>Dashboard last refreshed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
        <p style='margin: 0.25rem 0 0 0; font-size: 0.75rem;'>Protecting {stack_info['company_name']} | All systems operational</p>
    </div>
""", unsafe_allow_html=True)