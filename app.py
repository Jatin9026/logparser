import streamlit as st
import json
import csv
import io
import re
import time
import hashlib
import os
import requests
import ipaddress
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ============================================================
# ULPF — Universal Log Pre-processing Framework
# Single-file, deterministic, Streamlit application
# ============================================================

APP_NAME = "ULPF"
APP_VERSION = "2.0.0"
SCHEMA_VERSION = "2.0.0"

st.set_page_config(
    page_title="ULPF • Universal Log Pre-processing Framework",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ----------------------------- UI -----------------------------

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    --bg:#FFFFFF; --surface:#FFFFFF; --surface-soft:#FFF7ED; --surface-muted:#FAFAFA;
    --border:#F1D6BE; --border-strong:#FDBA74; --text:#111111;
    --muted:#666666; --muted-2:#8A8A8A;
    --primary:#F97316; --primary-hover:#EA580C; --primary-dark:#C2410C;
    --primary-soft:#FFF7ED; --success:#166534; --success-bg:#F0FDF4;
    --warning:#9A3412; --warning-bg:#FFF7ED; --danger:#B91C1C; --danger-bg:#FEF2F2;
    --shadow-sm:0 1px 3px rgba(17,17,17,.06),0 1px 2px rgba(17,17,17,.03);

    /* ---- Type scale: single source of truth for font sizing ---- */
    --fs-3xs:.70rem;   /* micro labels, badges */
    --fs-2xs:.75rem;   /* kpi labels, captions */
    --fs-xs:.80rem;    /* small-muted, mono, notes */
    --fs-sm:.87rem;    /* buttons, body-small */
    --fs-base:.95rem;  /* body text */
    --fs-md:1.05rem;   /* h4-h6, section subheads */
    --fs-lg:1.25rem;   /* h3 */
    --fs-xl:1.55rem;   /* h2, kpi values */
    --fs-2xl:2.05rem;  /* h1, hero title */

    --fw-regular:400; --fw-medium:500; --fw-semibold:600;
    --fw-bold:700; --fw-extrabold:800;
}

html,body,[class*="css"] {
    font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    font-size:var(--fs-base);
}
.stApp,[data-testid="stAppViewContainer"] { background:#FFFFFF; color:#111111; }
[data-testid="stHeader"] { background:rgba(255,255,255,.97); border-bottom:1px solid #F3F3F3; }
[data-testid="stSidebar"] { background:#FFFFFF; border-right:1px solid var(--border); box-shadow:4px 0 18px rgba(17,17,17,.025); }
[data-testid="stSidebar"] * { color:#111111; }
[data-testid="stSidebar"] [role="radiogroup"] > label {
    border-radius:9px; padding:8px 10px; margin:2px 0;
    font-size:var(--fs-sm); font-weight:var(--fw-medium);
}
[data-testid="stSidebar"] [role="radiogroup"] > label:hover { background:var(--primary-soft); color:var(--primary-dark); }

.block-container { padding-top:1.5rem; padding-bottom:3.5rem; max-width:1500px; }

/* ---- Consistent heading ramp (Streamlit maps subheader/header to h2/h3) ---- */
h1,h2,h3,h4,h5,h6 { color:#111111 !important; letter-spacing:-.02em; font-weight:var(--fw-bold); }
h1 { font-size:var(--fs-2xl) !important; font-weight:var(--fw-extrabold) !important; }
h2 { font-size:var(--fs-xl) !important; }
h3 { font-size:var(--fs-lg) !important; }
h4,h5,h6 { font-size:var(--fs-md) !important; }
p, li, label, span { font-size:var(--fs-base); }

.hero {
    background:#FFFFFF; border:1px solid var(--border); border-top:3px solid var(--primary);
    border-radius:14px; padding:24px 28px; margin-bottom:22px; box-shadow:var(--shadow-sm);
}
.hero-title {
    font-size:var(--fs-2xl); line-height:1.15; font-weight:var(--fw-extrabold);
    letter-spacing:-.04em; margin:0; color:#111111;
    display:flex; align-items:center; gap:10px;
}
.hero-sub { color:var(--muted); margin-top:7px; font-size:var(--fs-base); line-height:1.55; max-width:980px; }

.section {
    font-size:var(--fs-md); line-height:1.4; font-weight:var(--fw-bold); margin:24px 0 11px;
    color:#111111; padding-left:10px; border-left:3px solid var(--primary);
    display:flex; align-items:center; gap:7px;
}
.card,.kpi {
    background:#FFFFFF; border:1px solid var(--border); border-radius:12px; box-shadow:var(--shadow-sm);
}
.card { padding:17px; font-size:var(--fs-base); }
.card b { font-size:var(--fs-base); font-weight:var(--fw-bold); }
.kpi { padding:16px 18px; min-height:104px; position:relative; overflow:hidden; }
.kpi::before { content:""; position:absolute; left:0; top:0; bottom:0; width:3px; background:var(--primary); }
.kpi-label {
    color:var(--muted); font-size:var(--fs-2xs); line-height:1.3; font-weight:var(--fw-bold);
    letter-spacing:.06em; text-transform:uppercase; display:flex; align-items:center; gap:5px;
}
.kpi-value { color:#111111; font-size:var(--fs-xl); line-height:1.15; font-weight:var(--fw-extrabold); margin-top:7px; }
.kpi-note { color:var(--muted-2); font-size:var(--fs-2xs); line-height:1.35; margin-top:4px; }
.small-muted { color:var(--muted); font-size:var(--fs-xs); line-height:1.5; }
.mono { font-family:'JetBrains Mono',monospace; font-size:var(--fs-xs); }

.icon-inline { vertical-align:-3px; margin-right:6px; display:inline-block; flex-shrink:0; }
.icon-inline.tight { margin-right:4px; vertical-align:-2px; }

.status-success,.status-partial,.status-failed {
    display:inline-flex; align-items:center; gap:4px;
    padding:3px 9px; border-radius:999px; font-weight:var(--fw-bold); font-size:var(--fs-3xs);
}
.status-success { color:var(--success);background:var(--success-bg);border:1px solid #BBF7D0; }
.status-partial { color:var(--warning);background:var(--warning-bg);border:1px solid #FED7AA; }
.status-failed { color:var(--danger);background:var(--danger-bg);border:1px solid #FECACA; }

div[data-testid="stMetric"] { background:#FFFFFF;border:1px solid var(--border);border-radius:10px;padding:10px 14px;box-shadow:var(--shadow-sm); }
div[data-testid="stMetric"] label { color:var(--muted) !important;font-weight:var(--fw-semibold) !important; font-size:var(--fs-2xs) !important; text-transform:uppercase; letter-spacing:.04em; }
div[data-testid="stMetricValue"] { color:#111111 !important; font-size:var(--fs-lg) !important; font-weight:var(--fw-extrabold) !important; }

.stButton > button,.stDownloadButton > button {
    min-height:38px;border-radius:8px;border:1px solid var(--border-strong);
    font-weight:var(--fw-bold);font-size:var(--fs-sm);letter-spacing:-.01em;
}
.stButton > button:hover,.stDownloadButton > button:hover {
    border-color:var(--primary);color:var(--primary-dark);box-shadow:0 3px 10px rgba(249,115,22,.12);
}
.stButton > button[kind="primary"] { background:var(--primary);color:#FFFFFF;border-color:var(--primary); }
.stButton > button[kind="primary"]:hover { background:var(--primary-hover);color:#FFFFFF;border-color:var(--primary-hover); }

[data-baseweb="select"] > div,[data-baseweb="input"] > div,textarea,input { border-radius:8px !important; }
textarea,input { font-family:'JetBrains Mono',monospace !important; font-size:var(--fs-sm) !important; }
[data-testid="stFileUploader"] section { border:1px dashed var(--border-strong);border-radius:10px;background:#FFFCF9; }
[data-testid="stDataFrame"] { border:1px solid var(--border);border-radius:10px;overflow:hidden; font-size:var(--fs-sm); }
.stAlert { border-radius:9px; font-size:var(--fs-sm); }
.stAlert p { font-size:var(--fs-sm) !important; }
hr { border-color:#F1F1F1 !important; }
a { color:var(--primary-dark) !important; }


/* ============================================================
   PROFESSIONAL INFORMATION ARCHITECTURE — layout only
   Keeps the existing white/black/orange theme and functionality.
   ============================================================ */
.page-kicker {
    color: #C2410C; font-size: .72rem; font-weight: 800;
    letter-spacing: .10em; text-transform: uppercase; margin-bottom: 3px;
}
.page-title {
    color:#111; font-size:1.65rem; font-weight:800;
    letter-spacing:-.035em; margin:0;
}
.page-desc {
    color:#666; font-size:.88rem; line-height:1.45; margin:.25rem 0 0;
}
.workflow-strip {
    display:flex; flex-wrap:wrap; gap:7px; margin:10px 0 18px;
}
.workflow-step {
    border:1px solid #F1D6BE; background:#FFF7ED; color:#7C2D12;
    border-radius:999px; padding:5px 10px; font-size:.72rem; font-weight:700;
}
.workflow-arrow { color:#C2410C; font-weight:800; align-self:center; }
.subtle-card {
    background:#FFFCF9; border:1px solid #F1D6BE; border-radius:10px;
    padding:12px 14px; margin:8px 0;
}
.event-hero {
    border:1px solid #F1D6BE; border-left:4px solid #F97316;
    border-radius:10px; background:#FFF; padding:13px 15px; margin:8px 0 14px;
}
.event-title { font-size:1.02rem; font-weight:800; color:#111; }
.event-meta { font-size:.78rem; color:#666; margin-top:4px; }
.detail-label {
    font-size:.70rem; text-transform:uppercase; letter-spacing:.06em;
    font-weight:800; color:#777; margin-bottom:3px;
}

/* ============================================================
   STRICT LIGHT THEME — never allow dark text/background clashes
   ============================================================ */
[data-testid="stAppViewContainer"], [data-testid="stAppViewContainer"] * {
    color-scheme: light !important;
}
.stMarkdown, .stMarkdown p, .stMarkdown span, .stMarkdown li, .stMarkdown label,
[data-testid="stText"], [data-testid="stCaptionContainer"],
[data-testid="stWidgetLabel"], [data-testid="stWidgetLabel"] p {
    color:#111111 !important;
}
[data-testid="stWidgetLabel"] p { font-size:var(--fs-sm) !important; font-weight:var(--fw-semibold) !important; }
.stCaption, [data-testid="stCaptionContainer"] { color:#666666 !important; font-size:var(--fs-xs) !important; }

/* Inputs / selects / text areas */
input, textarea, [data-baseweb="input"] input, [data-baseweb="textarea"] textarea,
[data-baseweb="select"] input {
    background:#FFFFFF !important;
    color:#111111 !important;
    -webkit-text-fill-color:#111111 !important;
    caret-color:#F97316 !important;
}
input::placeholder, textarea::placeholder, [data-baseweb="input"] input::placeholder,
[data-baseweb="textarea"] textarea::placeholder {
    color:#777777 !important; opacity:1 !important;
    -webkit-text-fill-color:#777777 !important;
}
[data-baseweb="input"] > div, [data-baseweb="textarea"] > div,
[data-baseweb="select"] > div {
    background:#FFFFFF !important; color:#111111 !important;
    border-color:#FDBA74 !important;
}
[data-baseweb="select"] *, [data-baseweb="popover"] *,
[data-baseweb="menu"] *, [role="option"] {
    color:#111111 !important;
    background:#FFFFFF !important;
    font-size:var(--fs-sm) !important;
}
[data-baseweb="menu"] [aria-selected="true"], [role="option"]:hover {
    background:#FFF7ED !important; color:#C2410C !important;
}

/* Checkboxes, radio buttons, toggles */
[data-testid="stCheckbox"] label, [data-testid="stRadio"] label,
[data-testid="stToggle"] label { color:#111111 !important; font-size:var(--fs-sm) !important; }
[data-testid="stCheckbox"] label p, [data-testid="stRadio"] label p,
[data-testid="stToggle"] label p { color:#111111 !important; font-size:var(--fs-sm) !important; }

/* Buttons: light buttons = black text, orange primary = white text */
.stButton > button, .stDownloadButton > button,
button[kind="secondary"], button[kind="tertiary"] {
    background:#FFFFFF !important; color:#111111 !important;
    -webkit-text-fill-color:#111111 !important;
}
.stButton > button:hover, .stDownloadButton > button:hover,
button[kind="secondary"]:hover {
    background:#FFF7ED !important; color:#C2410C !important;
}
.stButton > button[kind="primary"], .stButton > button[kind="primary"] *,
button[kind="primary"], button[kind="primary"] * {
    background:#F97316 !important; color:#FFFFFF !important;
    -webkit-text-fill-color:#FFFFFF !important;
}

/* Expanders, tabs and containers */
[data-testid="stExpander"], [data-testid="stExpander"] details,
[data-testid="stExpander"] summary, [data-testid="stExpander"] > div {
    background:#FFFFFF !important; color:#111111 !important;
    border-color:#F1D6BE !important;
}
[data-testid="stExpander"] summary p, [data-testid="stExpander"] summary span {
    color:#111111 !important; font-size:var(--fs-sm) !important; font-weight:var(--fw-semibold) !important;
}
button[data-baseweb="tab"], [data-baseweb="tab-list"] button {
    background:#FFFFFF !important; color:#555555 !important; font-size:var(--fs-sm) !important;
}
button[data-baseweb="tab"][aria-selected="true"] {
    color:#C2410C !important; border-bottom-color:#F97316 !important;
}

/* File uploader */
[data-testid="stFileUploader"] section, [data-testid="stFileUploader"] section * {
    background:#FFFCF9 !important; color:#111111 !important;
}
[data-testid="stFileUploader"] button {
    background:#FFFFFF !important; color:#111111 !important; border-color:#FDBA74 !important;
}

/* Metrics / dataframes */
div[data-testid="stMetric"], div[data-testid="stMetric"] * {
    background:#FFFFFF !important;
}
div[data-testid="stMetricValue"], div[data-testid="stMetricValue"] * {
    color:#111111 !important; -webkit-text-fill-color:#111111 !important;
}
div[data-testid="stMetricLabel"], div[data-testid="stMetricLabel"] * {
    color:#666666 !important; -webkit-text-fill-color:#666666 !important;
}

/* Code/log blocks: white surface + black text; never black-on-black */
[data-testid="stCodeBlock"], [data-testid="stCodeBlock"] pre,
[data-testid="stCodeBlock"] code, pre, code {
    background:#FAFAFA !important; color:#111111 !important; font-size:var(--fs-xs) !important;
}

/* Alerts / status messages */
[data-testid="stAlert"] { color:#111111 !important; }
[data-testid="stAlert"] p, [data-testid="stAlert"] span { color:inherit !important; }

/* Streamlit header/menu text */
[data-testid="stHeader"] *, [data-testid="stToolbar"] * { color:#111111 !important; }

@media (max-width:900px) {
    .block-container{padding-left:1rem;padding-right:1rem;}
    .hero-title{font-size:1.8rem;}
    .kpi-value{font-size:1.45rem;}
}
</style>
""",
    unsafe_allow_html=True,
)

# ------------------------- Icon system --------------------------
# Inline stroke-based SVG icons (viewBox 24x24), rendered with `currentColor`
# so they inherit whichever text color the surrounding element already uses.
# No emoji, no external icon-font dependency.

ICON_PATHS: Dict[str, str] = {
    "bolt": '<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/>',
    "dashboard": '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
    "upload": '<path d="M12 3v12"/><path d="m7 8 5-5 5 5"/><path d="M5 21h14"/>',
    "search": '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    "git-branch": '<line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/>',
    "flask": '<path d="M9 2v6.5L4.5 17a2 2 0 0 0 1.8 3h11.4a2 2 0 0 0 1.8-3L15 8.5V2"/><path d="M9 2h6"/><path d="M8.5 12h7"/>',
    "trash": '<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/>',
    "download": '<path d="M12 15V3"/><path d="m7 10 5 5 5-5"/><path d="M20 21H4"/>',
    "check-circle": '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
    "alert-triangle": '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    "x-circle": '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
    "gauge": '<path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/>',
    "list": '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
    "database": '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
    "activity": '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
    "info": '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
    "layers": '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
}


def icon(name: str, size: int = 16, color: str = "currentColor", tight: bool = False) -> str:
    """Return an inline stroke-SVG icon that inherits the surrounding text color."""
    d = ICON_PATHS.get(name, "")
    if not d:
        return ""
    cls = "icon-inline tight" if tight else "icon-inline"
    return (
        f'<svg class="{cls}" xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" '
        f'viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="2" '
        f'stroke-linecap="round" stroke-linejoin="round">{d}</svg>'
    )


def section(text: str, icon_name: Optional[str] = None):
    """Render a consistent section heading, optionally prefixed with an icon."""
    ic = icon(icon_name, size=15) if icon_name else ""
    st.markdown(f'<div class="section">{ic}{text}</div>', unsafe_allow_html=True)


# -------------------------- Utilities -------------------------

def safe_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(float(str(value).strip()))
    except Exception:
        return None


def safe_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(str(value).strip())
    except Exception:
        return None


def clean_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value).strip()


def normalize_severity(value: Any) -> str:
    if value is None or value == "":
        return "INFO"
    s = str(value).strip().upper()
    mapping = {
        "0":"DEBUG","1":"INFO","2":"INFO","3":"NOTICE","4":"NOTICE",
        "5":"WARNING","6":"WARNING","7":"ERROR","8":"ERROR","9":"CRITICAL","10":"CRITICAL",
        "D":"DEBUG","DBG":"DEBUG","DEBUG":"DEBUG",
        "I":"INFO","INFO":"INFO","INFORMATIONAL":"INFO",
        "N":"NOTICE","NOTICE":"NOTICE",
        "W":"WARNING","WARN":"WARNING","WARNING":"WARNING",
        "E":"ERROR","ERR":"ERROR","ERROR":"ERROR",
        "C":"CRITICAL","CRIT":"CRITICAL","CRITICAL":"CRITICAL",
        "F":"CRITICAL","FATAL":"CRITICAL","ALERT":"CRITICAL",
        "EMERG":"EMERGENCY","EMERGENCY":"EMERGENCY",
        "LOW":"LOW","MEDIUM":"MEDIUM","HIGH":"HIGH","VERBOSE":"VERBOSE","V":"VERBOSE",
    }
    return mapping.get(s, s if s else "INFO")


def normalize_outcome(value: Any) -> str:
    if value is None or value == "":
        return ""
    s = str(value).strip().lower()
    if s in {"success","succeeded","ok","pass","passed","allow","allowed","accepted","accept","permit","permitted"}:
        return "SUCCESS"
    if s in {"failure","failed","fail","error","deny","denied","blocked","block","reject","rejected"}:
        return "FAILURE"
    if s in {"unknown","indeterminate"}:
        return "UNKNOWN"
    return s.upper()


def valid_ipv4(value: str) -> bool:
    try:
        return isinstance(value, str) and ipaddress.ip_address(value).version == 4
    except Exception:
        return False


def extract_ipv4(text: str) -> List[str]:
    found = re.findall(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        text,
    )
    return list(dict.fromkeys(found))


def extract_url(text: str) -> List[str]:
    return re.findall(r'https?://[^\s<>"{}|\\^`]+', text)


def extract_domain(text: str) -> List[str]:
    return re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[A-Za-z]{2,}\b', text)


def parse_timestamp(value: Any) -> str:
    """Normalize timestamps to one stable canonical display format."""
    if not value:
        return ""
    s = str(value).strip()

    if re.match(r"^\d{4}-\d{2}-\d{2}T", s):
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return dt.strftime("%Y-%m-%d %H:%M:%S") + (
                f".{dt.microsecond:06d}" if dt.microsecond else ""
            )
        except Exception:
            return s.replace("T", " ", 1).rstrip("Z")

    fmts = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
        "%Y-%m-%d",
        "%b %d %H:%M:%S",
        "%b  %d %H:%M:%S",
        "%b %d %Y %H:%M:%S",
    ]
    for fmt in fmts:
        try:
            dt = datetime.strptime(s, fmt)
            return dt.strftime("%Y-%m-%d %H:%M:%S") + (
                f".{dt.microsecond:06d}" if dt.microsecond else ""
            )
        except Exception:
            pass
    return s


def flatten_dict(obj: Any, prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                out.update(flatten_dict(v, path))
            elif isinstance(v, list) and v and isinstance(v[0], (dict, list)):
                out[path] = v
            else:
                out[path] = v
    else:
        out[prefix or "value"] = obj
    return out


def parse_kv_tokens(text: str) -> Dict[str, str]:
    # Handles key=value, key="value with spaces", and key='value with spaces'.
    pattern = re.compile(
        r'([A-Za-z_][\w.\-]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|(\S+))'
    )
    result = {}
    for m in pattern.finditer(text):
        result[m.group(1)] = m.group(2) if m.group(2) is not None else (
            m.group(3) if m.group(3) is not None else m.group(4)
        )
    return result


# ---------------------- Universal Event -----------------------

@dataclass
class UniversalEvent:
    event_id: str = ""
    raw_event_id: str = ""
    event_sequence: int = 0
    schema_version: str = SCHEMA_VERSION

    timestamp: str = ""
    timestamp_original: str = ""
    ingestion_timestamp: str = ""

    event_category: str = "unknown"
    event_type: str = "unclassified"
    event_action: str = ""
    event_outcome: str = ""
    severity: str = "INFO"

    source_ip: str = ""
    source_port: Optional[int] = None
    source_hostname: str = ""
    destination_ip: str = ""
    destination_port: Optional[int] = None
    destination_hostname: str = ""
    protocol: str = ""

    user_name: str = ""
    user_id: str = ""
    host_name: str = ""
    host_ip: str = ""
    operating_system: str = ""

    process_name: str = ""
    process_id: Optional[int] = None
    application_name: str = ""
    service_name: str = ""
    container_name: str = ""
    pod_name: str = ""
    namespace: str = ""

    http_method: str = ""
    http_status: Optional[int] = None
    url: str = ""
    domain: str = ""

    database_name: str = ""
    query_type: str = ""

    file_name: str = ""
    file_size: Optional[int] = None

    exception_type: str = ""
    source_file: str = ""
    line_number: Optional[int] = None
    thread_name: str = ""
    thread_id: str = ""

    tag: str = ""
    interface: str = ""
    logon_type: str = ""

    source_vendor: str = "unknown"
    source_product: str = ""
    source_version: str = ""
    source_format: str = "unknown"

    parser_name: str = ""
    parser_version: str = ""

    raw_event: str = ""
    raw_event_hash: str = ""

    processing_method: str = "deterministic"
    processing_chain: List[str] = field(default_factory=list)

    confidence: float = 0.0
    field_confidence: Dict[str, float] = field(default_factory=dict)
    field_provenance: Dict[str, str] = field(default_factory=dict)

    processing_time_ms: float = 0.0
    processing_status: str = "FAILED"
    validation_errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    extra_fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------- Semantic Mapper -----------------------

class SemanticMapper:
    ALIASES = {
        "timestamp": [
            "timestamp","time","@timestamp","datetime","date","event_time","event.time",
            "log.time","log_time","created","created_at"
        ],
        "host_name": [
            "host","hostname","device","server","node","host_name","computer",
            "computername","computer_name","machine","machine_name","server_name",
            "log.device"
        ],
        "source_ip": [
            "source_ip","src_ip","src","source.ip","client_ip","remote_ip","network.src",
            "network.source.ip","sourceip","sourceaddress","source_address","sip"
        ],
        "destination_ip": [
            "destination_ip","dst_ip","dst","destination.ip","dest_ip","server_ip",
            "network.dst","network.destination.ip","destinationip","destaddress","dip"
        ],
        "source_port": [
            "source_port","src_port","spt","source.port","client_port","sport"
        ],
        "destination_port": [
            "destination_port","dst_port","dpt","destination.port","server_port","dport"
        ],
        "protocol": ["protocol","proto","network.protocol","transport"],
        "user_name": [
            "user","username","user_name","user.name","account","login","user_name_value"
        ],
        "user_id": ["user_id","uid","user.id","account_id"],
        "process_name": ["process","process_name","process.name","app_name","program"],
        "process_id": ["pid","process_id","process.pid","processid"],
        "application_name": ["application","application_name","app","application.name"],
        "service_name": ["service_name","service","component","service.name"],
        "event_action": [
            "action","event_action","event.action","operation","activity","message",
            "msg","log.msg","event.message"
        ],
        "event_outcome": ["outcome","event_outcome","event.outcome","result","status"],
        "event_category": ["category","event_category","event.category","class"],
        "event_type": ["type","event_type","event.type","kind"],
        "severity": ["severity","level","priority","log_level","loglevel","log.severity"],
        "source_vendor": ["vendor","source_vendor","manufacturer","device.vendor"],
        "source_product": ["product","source_product","device.product"],
        "source_version": ["version","source_version","device.version"],
        "database_name": ["database","database_name","db","db_name"],
        "query_type": ["query_type","query","operation_type","statement_type"],
        "url": ["url","uri","request_url","link","cs1_url"],
        "domain": ["domain","hostname_fqdn","fqdn"],
        "http_method": ["http_method","method","request_method","http.request.method"],
        "http_status": ["http_status","status_code","http.response.status_code","response_code"],
        "container_name": ["container_name","container","docker_container"],
        "pod_name": ["pod_name","pod","k8s_pod"],
        "namespace": ["namespace","k8s_namespace","kubernetes_namespace"],
        "file_name": ["file","file_name","filename","file_path","path"],
        "file_size": ["size","file_size","bytes"],
        "exception_type": ["exception_type","exception","error_type","exception_class"],
        "source_file": ["source_file","file_source"],
        "line_number": ["line_number","line","lineno"],
        "thread_name": ["thread","thread_name"],
        "thread_id": ["thread_id","tid"],
        "tag": ["tag","log.tag"],
        "interface": ["interface","log.interface"],
        "logon_type": ["logon_type","LogonType"],
    }

    ALIAS_TO_FIELD: Dict[str, str] = {}
    for canonical, aliases in ALIASES.items():
        for alias in aliases:
            ALIAS_TO_FIELD[alias.lower()] = canonical

    @classmethod
    def map_field(cls, key: str) -> Optional[str]:
        k = str(key).strip().lower()
        if k in cls.ALIAS_TO_FIELD:
            return cls.ALIAS_TO_FIELD[k]
        # Prefer the most meaningful suffix for nested structures.
        if "." in k:
            leaf = k.split(".")[-1]
            if leaf in cls.ALIAS_TO_FIELD:
                return cls.ALIAS_TO_FIELD[leaf]
        combined = k.replace(".", "_")
        return cls.ALIAS_TO_FIELD.get(combined)


NUMERIC_FIELDS = {
    "source_port","destination_port","process_id","http_status","file_size","line_number"
}


# ---------------------- Format Detection ----------------------

class FormatDetector:
    def detect(self, raw: str) -> Dict[str, Any]:
        s = raw.strip()
        if not s:
            return {"format":"empty","confidence":1.0,"reason":"Empty input"}

        if s.startswith("CEF:") and "|" in s:
            return {"format":"cef","confidence":0.995,"reason":"CEF header"}
        if s.startswith("LEEF:") and "|" in s:
            return {"format":"leef","confidence":0.995,"reason":"LEEF header"}

        if s.startswith("{") or s.startswith("["):
            try:
                obj = json.loads(s)
                if isinstance(obj, dict):
                    return {"format":"json","confidence":0.995,"reason":"Valid JSON object"}
                if isinstance(obj, list):
                    return {"format":"json_array","confidence":0.995,"reason":"JSON array"}
            except Exception:
                pass

        if re.match(r"^\s*<\?xml\b", s, re.I) or (
            s.startswith("<") and s.endswith(">") and re.search(r"</[A-Za-z_][^>]*>\s*$", s)
        ):
            return {"format":"xml","confidence":0.98,"reason":"XML structure"}

        if re.match(r"^<\d+>\d+\s+", s):
            return {"format":"syslog_rfc5424","confidence":0.98,"reason":"RFC5424 syslog"}

        if re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+(?:\[\d+\])?:", s):
            return {"format":"syslog_rfc3164","confidence":0.98,"reason":"RFC3164 syslog"}

        if re.match(r"^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\d+\s+\d+\s+[VDIWEF]\s+\S+:", s):
            return {"format":"android_logcat","confidence":0.97,"reason":"Android logcat"}

        if re.match(r"^\[[^\]]+\]\s+\[[^\]]+\]\s+[^:]+:\s+", s):
            return {"format":"applog","confidence":0.92,"reason":"Bracketed application log"}

        if re.match(r'^\S+\s+\S+\s+\S+\s+\[[^\]]+\]\s+"[A-Z]+\s+', s):
            return {"format":"apache","confidence":0.95,"reason":"Apache access log"}

        # Timestamp + CSV is checked before generic timestamp.
        if re.match(r"^\d{4}-\d{2}-\d{2}[T\s]", s) and "," in s:
            return {"format":"csv","confidence":0.92,"reason":"Timestamped CSV"}

        if "\t" in s and s.count("\t") >= 2:
            return {"format":"tsv","confidence":0.82,"reason":"Tab-delimited"}

        if s.count("|") >= 3:
            return {"format":"pipe_delimited","confidence":0.78,"reason":"Pipe-delimited"}

        if re.search(r"\b[A-Za-z_][\w.\-]*\s*=\s*(?:\"[^\"]*\"|'[^']*'|\S+)", s):
            pairs = parse_kv_tokens(s)
            if len(pairs) >= 2:
                return {"format":"key_value","confidence":0.9,"reason":"Key=value pairs"}

        if re.match(r"^\d{4}-\d{2}-\d{2}[T\s]", s):
            return {"format":"timestamped","confidence":0.7,"reason":"Timestamped text"}

        return {"format":"unknown","confidence":0.25,"reason":"No known structure"}


# --------------------------- Parsers ---------------------------

class BaseParser:
    parser_name = "base"
    parser_version = "1.0"

    def parse(self, raw: str) -> Dict[str, Any]:
        return {"extra_fields":{}, "field_provenance":{}}


class JSONParser(BaseParser):
    parser_name = "json_parser"
    parser_version = "3.0"

    def parse(self, raw: str) -> Dict[str, Any]:
        result = {"extra_fields":{}, "field_provenance":{}}
        data = json.loads(raw)
        flat = flatten_dict(data)

        for path, value in flat.items():
            mapped = SemanticMapper.map_field(path)
            if mapped:
                self._set(result, mapped, value, path)
            else:
                result["extra_fields"][path] = value

        # Explicit semantic paths override weak leaf aliases.
        priority_paths = [
            ("event.action","event_action"),
            ("event.outcome","event_outcome"),
            ("event.category","event_category"),
            ("event.type","event_type"),
            ("event.reason","reason"),
            ("event.id","event_id_source"),
            ("user.name","user_name"),
            ("user.id","user_id"),
            ("source.ip","source_ip"),
            ("source.port","source_port"),
            ("destination.ip","destination_ip"),
            ("destination.port","destination_port"),
            ("network.src","source_ip"),
            ("network.dst","destination_ip"),
            ("network.protocol","protocol"),
            ("log.time","timestamp"),
            ("log.device","host_name"),
            ("log.msg","event_action"),
            ("log.severity","severity"),
            ("log.interface","interface"),
        ]
        for path, field_name in priority_paths:
            if path in flat:
                if field_name in UniversalEvent.__dataclass_fields__:
                    self._set(result, field_name, flat[path], path)
                else:
                    result["extra_fields"][field_name] = flat[path]

        return result

    def _set(self, result: Dict[str, Any], field: str, value: Any, path: str):
        if field in NUMERIC_FIELDS:
            value = safe_int(value)
        elif field == "timestamp":
            value = parse_timestamp(value)
        elif field == "severity":
            value = normalize_severity(value)
        elif field == "event_outcome":
            value = normalize_outcome(value)
        else:
            value = clean_string(value)
        result[field] = value
        result["field_provenance"][field] = path


class XMLParser(BaseParser):
    parser_name = "xml_parser"
    parser_version = "3.0"

    def parse(self, raw: str) -> Dict[str, Any]:
        result = {"extra_fields":{}, "field_provenance":{}}
        root = ET.fromstring(raw)

        for elem in root.iter():
            tag = elem.tag.split("}")[-1]
            text = (elem.text or "").strip()
            if text:
                mapped = SemanticMapper.map_field(tag)
                if mapped:
                    value = safe_int(text) if mapped in NUMERIC_FIELDS else text
                    if mapped == "severity":
                        value = normalize_severity(value)
                    if mapped == "event_outcome":
                        value = normalize_outcome(value)
                    result[mapped] = value
                    result["field_provenance"][mapped] = tag
                else:
                    result["extra_fields"][tag] = text

            for attr, value in elem.attrib.items():
                mapped = SemanticMapper.map_field(attr)
                if mapped:
                    result[mapped] = safe_int(value) if mapped in NUMERIC_FIELDS else value
                    result["field_provenance"][mapped] = f"{tag}.{attr}"
                else:
                    result["extra_fields"][f"{tag}.{attr}"] = value

        # SQL/query semantics from action or query text.
        blob = raw.upper()
        q = re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b", blob)
        if q:
            result["query_type"] = q.group(1)
            result["field_provenance"]["query_type"] = "SQL keyword"

        return result


class CSVParser(BaseParser):
    parser_name = "csv_parser"
    parser_version = "3.0"

    def parse(self, raw: str) -> Dict[str, Any]:
        result = {"extra_fields":{}, "field_provenance":{}}
        delim = "\t" if "\t" in raw else ("," if "," in raw else "|")
        row = next(csv.reader([raw], delimiter=delim))
        row = [x.strip() for x in row]

        # First use explicit key=value cells.
        for idx, cell in enumerate(row):
            if "=" in cell:
                k, v = cell.split("=",1)
                self._map(result, k.strip(), v.strip(), f"col_{idx}")

        # Known positional layout used by common SIEM exports.
        if row:
            if len(row) >= 1 and re.match(r"^\d{4}-\d{2}-\d{2}", row[0]):
                result["timestamp"] = row[0]
                result["field_provenance"]["timestamp"] = "col_0"
        if len(row) >= 2 and normalize_severity(row[1]) in {
            "DEBUG","INFO","NOTICE","WARNING","ERROR","CRITICAL","EMERGENCY"
        }:
            result["severity"] = normalize_severity(row[1])
            result["field_provenance"]["severity"] = "col_1"
        if len(row) >= 3 and row[2] and not valid_ipv4(row[2]):
            result["host_name"] = row[2]
            result["field_provenance"]["host_name"] = "col_2"
        if len(row) >= 4:
            result["extra_fields"].setdefault("source_category", row[3])
        if len(row) >= 5 and row[4]:
            result["extra_fields"]["event_id"] = row[4]
        if len(row) >= 6 and row[5]:
            result["event_action"] = row[5]
            result["field_provenance"]["event_action"] = "col_5"

        # Positional values after the header area.
        ips = [x for x in row if valid_ipv4(x)]
        if ips:
            result["source_ip"] = ips[0]
            result["field_provenance"]["source_ip"] = f"col_{row.index(ips[0])}"
        if len(ips) > 1:
            result["destination_ip"] = ips[1]
            result["field_provenance"]["destination_ip"] = f"col_{row.index(ips[1])}"

        # Generic semantic guesses for remaining cells.
        for idx, cell in enumerate(row):
            low = cell.lower()
            if not cell:
                continue
            if low.startswith("user="):
                self._map(result, "user", cell.split("=",1)[1], f"col_{idx}")
            elif low.startswith("process="):
                self._map(result, "process", cell.split("=",1)[1], f"col_{idx}")
            elif low.startswith("logontype="):
                self._map(result, "logon_type", cell.split("=",1)[1], f"col_{idx}")

        return result

    def _map(self, result, key, value, provenance):
        mapped = SemanticMapper.map_field(key)
        if mapped:
            result[mapped] = safe_int(value) if mapped in NUMERIC_FIELDS else value
            if mapped == "severity":
                result[mapped] = normalize_severity(value)
            if mapped == "event_outcome":
                result[mapped] = normalize_outcome(value)
            result["field_provenance"][mapped] = provenance
        else:
            result["extra_fields"][key.lower()] = value


class CEFParser(BaseParser):
    parser_name = "cef_parser"
    parser_version = "3.0"

    SEVERITY = {
        0:"DEBUG",1:"INFO",2:"INFO",3:"NOTICE",4:"NOTICE",
        5:"WARNING",6:"WARNING",7:"ERROR",8:"ERROR",9:"CRITICAL",10:"CRITICAL"
    }

    def parse(self, raw: str) -> Dict[str, Any]:
        result = {"extra_fields":{}, "field_provenance":{}}
        parts = raw.strip().split("|", 7)
        if len(parts) < 8 or not parts[0].startswith("CEF:"):
            raise ValueError("Invalid CEF record")

        result["source_vendor"] = parts[1]
        result["source_product"] = parts[2]
        result["source_version"] = parts[3]
        result["event_type"] = parts[5]

        sev = safe_int(parts[6])
        result["severity"] = self.SEVERITY.get(sev, normalize_severity(parts[6]))
        result["extra_fields"]["cef_severity_original"] = sev if sev is not None else parts[6]

        ext = parse_kv_tokens(parts[7])
        for key, value in ext.items():
            k = key.lower()
            if k == "act":
                result["event_outcome"] = normalize_outcome(value)
                result["event_action"] = value
                result["field_provenance"]["event_outcome"] = "act"
                result["field_provenance"]["event_action"] = "act"
                continue

            # CEF extension aliases.
            special = {
                "src":"source_ip","dst":"destination_ip","spt":"source_port","dpt":"destination_port",
                "proto":"protocol","dhost":"destination_hostname","shost":"source_hostname",
                "request":"url","requestmethod":"http_method","status":"http_status",
                "suser":"user_name","duser":"user_name",
            }
            mapped = special.get(k) or SemanticMapper.map_field(k)
            if mapped:
                result[mapped] = safe_int(value) if mapped in NUMERIC_FIELDS else value
                if mapped == "event_outcome":
                    result[mapped] = normalize_outcome(value)
                result["field_provenance"][mapped] = key
            else:
                result["extra_fields"][key] = value

        return result


class LEEFParser(BaseParser):
    parser_name = "leef_parser"
    parser_version = "3.0"

    def parse(self, raw: str) -> Dict[str, Any]:
        result = {"extra_fields":{}, "field_provenance":{}}
        parts = raw.strip().split("|", 6)
        if len(parts) < 7 or not parts[0].startswith("LEEF:"):
            raise ValueError("Invalid LEEF record")

        result["source_vendor"] = parts[1]
        result["source_product"] = parts[2]
        result["source_version"] = parts[3]
        result["event_type"] = parts[4]
        delimiter = parts[5] or "\t"

        for pair in parts[6].split(delimiter):
            if "=" not in pair:
                continue
            k,v = pair.split("=",1)
            mapped = SemanticMapper.map_field(k)
            if mapped:
                result[mapped] = safe_int(v) if mapped in NUMERIC_FIELDS else v
                if mapped == "severity":
                    result[mapped] = normalize_severity(v)
                if mapped == "event_outcome":
                    result[mapped] = normalize_outcome(v)
                result["field_provenance"][mapped] = k
            else:
                result["extra_fields"][k] = v
        return result


class SyslogParser(BaseParser):
    parser_name = "syslog_parser"
    parser_version = "3.0"

    def parse(self, raw: str) -> Dict[str, Any]:
        result = {"extra_fields":{}, "field_provenance":{}}

        # RFC5424
        m = re.match(
            r"^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$",
            raw.strip()
        )
        if m:
            pri = int(m.group(1))
            result["severity"] = normalize_severity(str(pri % 8))
            result["timestamp"] = m.group(3)
            result["host_name"] = m.group(4)
            result["application_name"] = m.group(5)
            result["process_id"] = safe_int(m.group(6)) if m.group(6) != "-" else None
            result["event_action"] = m.group(7).strip()
            result["field_provenance"].update({
                "timestamp":"syslog.timestamp","host_name":"syslog.hostname",
                "application_name":"syslog.app","process_id":"syslog.procid",
                "event_action":"syslog.msg"
            })
            self._message_semantics(result, result["event_action"])
            return result

        # RFC3164
        m = re.match(
            r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([A-Za-z0-9_.@/-]+)(?:\[(\d+)\])?:\s*(.*)$",
            raw.strip()
        )
        if not m:
            raise ValueError("Invalid syslog record")

        result["timestamp"] = m.group(1)
        result["host_name"] = m.group(2)
        result["process_name"] = m.group(3)
        result["process_id"] = safe_int(m.group(4))
        message = m.group(5)

        result["field_provenance"].update({
            "timestamp":"syslog.header",
            "host_name":"syslog.hostname",
            "process_name":"syslog.app",
            "process_id":"syslog.pid",
            "event_action":"syslog.message",
        })

        self._message_semantics(result, message)
        result["event_action"] = message[:500]
        result["extra_fields"]["full_message"] = message
        return result

    def _message_semantics(self, result: Dict[str,Any], message: str):
        low = message.lower()

        if "failed password" in low or "authentication failure" in low or "invalid password" in low or "login failed" in low:
            result["event_category"] = "authentication"
            result["event_type"] = "authentication_failure"
            result["event_outcome"] = "FAILURE"
        elif "accepted password" in low or "accepted publickey" in low or "login success" in low or "session opened" in low:
            result["event_category"] = "authentication"
            result["event_type"] = "authentication_success"
            result["event_outcome"] = "SUCCESS"
        elif "ssh" in low:
            result["event_category"] = "authentication"
            result["event_type"] = "ssh_event"

        if "ssh" in low or result.get("process_name","").lower() == "sshd":
            result["protocol"] = "SSH"
            result["field_provenance"]["protocol"] = "message"

        ips = extract_ipv4(message)
        if ips:
            result["source_ip"] = ips[0]
            result["field_provenance"]["source_ip"] = "message.ip"
        p = re.search(r"\bport\s+(\d+)", message, re.I)
        if p:
            result["source_port"] = safe_int(p.group(1))
            result["field_provenance"]["source_port"] = "message.port"

        # "for invalid user root" and "for root".
        u = re.search(r"\bfor\s+(?:invalid\s+user\s+)?([A-Za-z0-9_.@-]+)", message, re.I)
        if u:
            result["user_name"] = u.group(1)
            result["field_provenance"]["user_name"] = "message.user"

        if "error" in low and result.get("event_category") == "unknown":
            result["event_category"] = "system"
            result["event_type"] = "system_error"


class KeyValueParser(BaseParser):
    parser_name = "keyvalue_parser"
    parser_version = "3.0"

    def parse(self, raw: str) -> Dict[str, Any]:
        result = {"extra_fields":{}, "field_provenance":{}}
        text = raw.strip()

        ts = re.match(r"^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)", text)
        if ts:
            result["timestamp"] = ts.group(1)
            result["field_provenance"]["timestamp"] = "prefix"

        sev = re.search(r"\[(DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|CRITICAL|FATAL)\]", text, re.I)
        if sev:
            result["severity"] = normalize_severity(sev.group(1))
            result["field_provenance"]["severity"] = "bracket"

        pairs = parse_kv_tokens(text)
        for key, value in pairs.items():
            mapped = SemanticMapper.map_field(key)
            if mapped:
                result[mapped] = safe_int(value) if mapped in NUMERIC_FIELDS else value
                if mapped == "severity":
                    result[mapped] = normalize_severity(value)
                if mapped == "event_outcome":
                    result[mapped] = normalize_outcome(value)
                if mapped == "timestamp":
                    result[mapped] = parse_timestamp(value)
                result["field_provenance"][mapped] = key
            else:
                result["extra_fields"][key] = value

        return result


class ApacheParser(BaseParser):
    parser_name = "apache_parser"
    parser_version = "3.0"

    def parse(self, raw: str) -> Dict[str, Any]:
        result = {"extra_fields":{}, "field_provenance":{}}
        m = re.match(
            r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+([^"]+)"\s+(\d{3})\s+(\S+)',
            raw
        )
        if not m:
            raise ValueError("Invalid Apache/Nginx access log")
        result["source_ip"] = m.group(1)
        result["timestamp"] = m.group(2)
        result["http_method"] = m.group(3)
        result["url"] = m.group(4)
        result["protocol"] = m.group(5)
        result["http_status"] = safe_int(m.group(6))
        result["event_category"] = "web"
        result["event_type"] = "http_request"
        result["event_action"] = f"{m.group(3)} {m.group(4)}"
        result["event_outcome"] = "SUCCESS" if 200 <= int(m.group(6)) < 400 else "FAILURE"
        result["field_provenance"] = {
            "source_ip":"access.client_ip","timestamp":"access.timestamp",
            "http_method":"request.method","url":"request.url","protocol":"request.protocol",
            "http_status":"response.status","event_action":"request"
        }
        return result


class AndroidLogcatParser(BaseParser):
    parser_name = "android_logcat_parser"
    parser_version = "3.0"

    def parse(self, raw: str) -> Dict[str, Any]:
        result = {"extra_fields":{}, "field_provenance":{}}
        m = re.match(
            r"^(\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+([^:]+):\s*(.*)$",
            raw
        )
        if not m:
            raise ValueError("Invalid Android Logcat record")

        result["timestamp"] = f"2026-{m.group(1)} {m.group(2)}"
        result["process_id"] = safe_int(m.group(3))
        result["thread_id"] = m.group(4)
        result["severity"] = normalize_severity(m.group(5))
        result["tag"] = m.group(6).strip()
        result["process_name"] = m.group(6).strip()
        message = m.group(7)

        result["event_category"] = "android"
        result["event_type"] = "system"
        result["event_action"] = message[:500]
        result["field_provenance"].update({
            "timestamp":"logcat.timestamp","process_id":"logcat.pid",
            "thread_id":"logcat.tid","severity":"logcat.priority",
            "tag":"logcat.tag","process_name":"logcat.tag","event_action":"logcat.message"
        })

        exc = re.search(r"\b([\w.]+(?:Exception|Error))\b", message)
        if exc:
            result["exception_type"] = exc.group(1)
            result["event_type"] = "application_error"
            result["event_category"] = "application"
            result["field_provenance"]["exception_type"] = "message.exception"

        proc = re.search(r"Process:\s*([^,\s]+),\s*PID:\s*(\d+)", message, re.I)
        if proc:
            result["application_name"] = proc.group(1)
            result["process_id"] = safe_int(proc.group(2))
            result["field_provenance"]["application_name"] = "message.process"

        th = re.search(r"FATAL EXCEPTION:\s*([^\s]+)", message, re.I)
        if th:
            result["thread_name"] = th.group(1)
            result["field_provenance"]["thread_name"] = "message.thread"

        src = re.search(r"\(([^():]+\.java):(\d+)\)", message)
        if src:
            result["source_file"] = src.group(1)
            result["line_number"] = safe_int(src.group(2))
            result["field_provenance"]["source_file"] = "stacktrace.file"
            result["field_provenance"]["line_number"] = "stacktrace.line"

        return result


class ApplicationLogParser(BaseParser):
    parser_name = "applog_parser"
    parser_version = "3.0"

    def parse(self, raw: str) -> Dict[str, Any]:
        result = {"extra_fields":{}, "field_provenance":{}}
        m = re.match(r"^\[([^\]]+)\]\s+\[([^\]]+)\]\s+([^:]+):\s*(.*)$", raw)
        if not m:
            raise ValueError("Invalid application log")

        result["timestamp"] = m.group(1).strip()
        result["severity"] = normalize_severity(m.group(2))
        result["service_name"] = m.group(3).strip()
        rest = m.group(4).strip()

        result["field_provenance"].update({
            "timestamp":"prefix.timestamp","severity":"prefix.severity",
            "service_name":"prefix.service"
        })

        # Preserve the complete message while extracting kv suffixes.
        pairs = parse_kv_tokens(rest)
        msg = re.sub(
            r'\b[A-Za-z_][\w.\-]*\s*=\s*(?:"[^"]*"|\'[^\']*\'|\S+)',
            "",
            rest
        ).strip(" ;")
        result["event_action"] = msg[:500]
        result["field_provenance"]["event_action"] = "message"

        for key,value in pairs.items():
            mapped = SemanticMapper.map_field(key)
            if mapped:
                result[mapped] = safe_int(value) if mapped in NUMERIC_FIELDS else value
                if mapped == "severity":
                    result[mapped] = normalize_severity(value)
                result["field_provenance"][mapped] = key
            else:
                result["extra_fields"][key] = value

        # db=postgresql://10.40.2.15:5432/payments
        db = pairs.get("db")
        if db:
            # Explicit host= is authoritative. The DB URL endpoint is host_ip
            # when it is an IP, and must never overwrite host_name.
            hm = re.search(r"://([^:/]+)", db)
            if hm:
                db_host = hm.group(1)
                if valid_ipv4(db_host):
                    if not result.get("host_ip"):
                        result["host_ip"] = db_host
                        result["field_provenance"]["host_ip"] = "db.url"
                elif not result.get("host_name"):
                    result["host_name"] = db_host
                    result["field_provenance"]["host_name"] = "db.url"
            dm = re.search(r"/([^/?]+)$", db)
            if dm:
                result["database_name"] = dm.group(1)
                result["field_provenance"]["database_name"] = "db.url"

        if "connection pool exhausted" in rest.lower():
            result["event_category"] = "application"
            result["event_type"] = "application_availability"
            result["event_outcome"] = "FAILURE"
        elif result["severity"] in {"ERROR","CRITICAL"}:
            result["event_category"] = "application"
            result["event_type"] = "application_error"

        return result


class GenericParser(BaseParser):
    parser_name = "generic_parser"
    parser_version = "3.0"

    def parse(self, raw: str) -> Dict[str, Any]:
        result = {"extra_fields":{}, "field_provenance":{}}
        ts = re.match(r"^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?)", raw)
        if ts:
            result["timestamp"] = ts.group(1)
            result["field_provenance"]["timestamp"] = "prefix"

        sev = re.search(r"\[(DEBUG|INFO|NOTICE|WARNING|WARN|ERROR|ERR|CRITICAL|FATAL)\]", raw, re.I)
        if sev:
            result["severity"] = normalize_severity(sev.group(1))
            result["field_provenance"]["severity"] = "bracket"

        ips = extract_ipv4(raw)
        if ips:
            result["source_ip"] = ips[0]
            result["field_provenance"]["source_ip"] = "message.ip"
        if len(ips) > 1:
            result["destination_ip"] = ips[1]
            result["field_provenance"]["destination_ip"] = "message.ip"

        urls = extract_url(raw)
        if urls:
            result["url"] = urls[0]
            result["field_provenance"]["url"] = "message.url"

        pairs = parse_kv_tokens(raw)
        for key,value in pairs.items():
            mapped = SemanticMapper.map_field(key)
            if mapped and mapped not in result:
                result[mapped] = safe_int(value) if mapped in NUMERIC_FIELDS else value
                result["field_provenance"][mapped] = key

        result["event_action"] = raw[:500]
        return result


PARSER_BY_FORMAT = {
    "json": JSONParser(),
    "cef": CEFParser(),
    "leef": LEEFParser(),
    "xml": XMLParser(),
    "csv": CSVParser(),
    "tsv": CSVParser(),
    "pipe_delimited": CSVParser(),
    "syslog_rfc3164": SyslogParser(),
    "syslog_rfc5424": SyslogParser(),
    "apache": ApacheParser(),
    "android_logcat": AndroidLogcatParser(),
    "applog": ApplicationLogParser(),
    "key_value": KeyValueParser(),
    "timestamped": GenericParser(),
    "unknown": GenericParser(),
}


# -------------------------- Taxonomy ---------------------------

class TaxonomyClassifier:
    @staticmethod
    def classify(event: UniversalEvent, raw: str):
        text = raw.lower()
        action = event.event_action.lower()

        # Strong semantic signals first.
        if event.event_category == "authentication" and event.event_type.startswith("authentication_"):
            return

        if (
            "failed password" in text or "invalid password" in text or
            "authentication failure" in text or "login failed" in text or
            ("event.action" in text and "login" in text and "failed" in text)
        ):
            event.event_category = "authentication"
            event.event_type = "authentication_failure"
            event.event_outcome = event.event_outcome or "FAILURE"
            return

        if (
            "accepted password" in text or "successful login" in text or
            "authentication success" in text or "session opened" in text
        ):
            event.event_category = "authentication"
            event.event_type = "authentication_success"
            event.event_outcome = event.event_outcome or "SUCCESS"
            return

        if event.query_type or re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b", raw, re.I):
            event.event_category = "database"
            event.event_type = "database_query"
            if not event.query_type:
                q = re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b", raw, re.I)
                if q:
                    event.query_type = q.group(1).upper()
            return

        if event.file_name or re.search(r"\b(file[_ -]?(download|upload|access|created|deleted|modified))\b", text):
            event.event_category = "file"
            event.event_type = "file_operation"
            return

        if event.http_method or event.http_status is not None or "http request" in text:
            event.event_category = "web"
            event.event_type = "http_request"
            return

        if event.interface or (
            event.source_ip and event.destination_ip and event.protocol
        ) or re.search(r"\b(interface down|interface up|link down|link up)\b", text):
            event.event_category = "network"
            event.event_type = "network_event"
            return

        if event.exception_type or "exception" in text or "stack trace" in text:
            event.event_category = "application"
            event.event_type = "application_error"
            return

        if "database connection pool exhausted" in text:
            event.event_category = "application"
            event.event_type = "application_availability"
            event.event_outcome = event.event_outcome or "FAILURE"
            return

        if event.event_category == "unknown" and event.severity in {"ERROR","CRITICAL"}:
            event.event_category = "application"
            event.event_type = "application_error"


# -------------------------- Validator --------------------------

class Validator:
    def validate(self, event: UniversalEvent) -> List[str]:
        errors = []

        for f in ("source_port","destination_port"):
            value = getattr(event,f)
            if value is not None and not 0 <= value <= 65535:
                errors.append(f"{f} out of range: {value}")

        for f in ("source_ip","destination_ip","host_ip"):
            value = getattr(event,f)
            if value and not valid_ipv4(value):
                errors.append(f"Invalid {f}: {value}")

        if event.http_status is not None and not 100 <= event.http_status <= 599:
            errors.append(f"Invalid http_status: {event.http_status}")

        if event.file_size is not None and event.file_size < 0:
            errors.append(f"Negative file_size: {event.file_size}")

        if not 0 <= event.confidence <= 1:
            errors.append(f"Confidence outside [0,1]: {event.confidence}")
            event.confidence = max(0.0,min(1.0,event.confidence))

        return errors



# -------------------- OpenRouter semantic layer ------------------
# OpenRouter provides an OpenAI-compatible API and supports structured JSON
# outputs through the chat/completions endpoint.
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "openai/gpt-5")
OPENROUTER_SITE_URL = os.getenv("OPENROUTER_SITE_URL", "")
OPENROUTER_SITE_NAME = os.getenv("OPENROUTER_SITE_NAME", "ULPF")

def _get_openrouter_api_key() -> str:
    """Read the OpenRouter key from Streamlit secrets or the environment.
    Never hard-code credentials into the application source."""
    try:
        key = st.secrets.get("OPENROUTER_API_KEY", os.getenv("OPENROUTER_API_KEY"))
    except Exception:
        key = os.getenv("OPENROUTER_API_KEY")
    if not key:
        key = os.getenv("OPENROUTER_API_KEY", os.getenv("OPENROUTER_API_KEY"))
    return str(key or "").strip()

def _openrouter_schema() -> Dict[str, Any]:
    fields = {
        "source_format": {"type":"string"},
        "event_category": {"type":"string"},
        "event_type": {"type":"string"},
        "event_action": {"type":"string"},
        "event_outcome": {"type":"string"},
        "severity": {"type":"string"},
        "timestamp": {"type":"string"},
        "source_ip": {"type":"string"},
        "source_port": {"type":["integer","null"]},
        "source_hostname": {"type":"string"},
        "destination_ip": {"type":"string"},
        "destination_port": {"type":["integer","null"]},
        "destination_hostname": {"type":"string"},
        "protocol": {"type":"string"},
        "user_name": {"type":"string"},
        "user_id": {"type":"string"},
        "host_name": {"type":"string"},
        "host_ip": {"type":"string"},
        "operating_system": {"type":"string"},
        "process_name": {"type":"string"},
        "process_id": {"type":["integer","null"]},
        "application_name": {"type":"string"},
        "service_name": {"type":"string"},
        "container_name": {"type":"string"},
        "pod_name": {"type":"string"},
        "namespace": {"type":"string"},
        "http_method": {"type":"string"},
        "http_status": {"type":["integer","null"]},
        "url": {"type":"string"},
        "domain": {"type":"string"},
        "database_name": {"type":"string"},
        "query_type": {"type":"string"},
        "file_name": {"type":"string"},
        "file_size": {"type":["integer","null"]},
        "exception_type": {"type":"string"},
        "source_file": {"type":"string"},
        "line_number": {"type":["integer","null"]},
        "thread_name": {"type":"string"},
        "thread_id": {"type":"string"},
        "tag": {"type":"string"},
        "interface": {"type":"string"},
        "logon_type": {"type":"string"},
        "source_vendor": {"type":"string"},
        "source_product": {"type":"string"},
        "source_version": {"type":"string"},
        "reason": {"type":"string"},
        "extra_fields": {
            "type":"object",
            "additionalProperties":{"type":"string"}
        },
        "field_provenance": {
            "type":"object",
            "additionalProperties":{"type":"string"}
        },
        "field_confidence": {
            "type":"object",
            "additionalProperties":{"type":"number"}
        },
        "ai_explanation": {"type":"string"}
    }
    return {
        "type":"object",
        "additionalProperties":False,
        "properties":fields,
        "required":list(fields.keys())
    }

def _extract_openrouter_text(payload: Dict[str, Any]) -> str:
    """Extract content from OpenRouter's OpenAI-compatible chat response."""
    choices = payload.get("choices", [])
    if choices:
        message = choices[0].get("message", {}) or {}
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            return content
        # Some providers may return structured content blocks.
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    parts.append(item["text"])
            if parts:
                return "".join(parts)
    raise ValueError("OpenRouter response did not contain message content")

def openrouter_normalize_event(
    raw: str,
    detected_format: str,
    detected_confidence: float,
    deterministic_fields: Dict[str, Any],
) -> Dict[str, Any]:
    """Use OpenRouter structured JSON output as ULPF semantic normalization.

    The model receives the raw event plus deterministic parser evidence.
    The raw event remains authoritative and is never replaced.
    """
    key = _get_openrouter_api_key()
    if not key:
        raise RuntimeError(
            "OPENROUTER_API_KEY is not configured. Add it to Streamlit Secrets "
            "or the OPENROUTER_API_KEY environment variable."
        )

    evidence = {
        k: v for k, v in deterministic_fields.items()
        if k not in {"raw_event","raw_event_hash"} and v not in ("", None, {}, [])
    }

    developer_prompt = """
You are the semantic normalization engine inside ULPF (Universal Log Pre-processing Framework).

Your job is NOT to write a summary. Your job is to convert ONE raw enterprise log event
into the supplied Universal Event schema.

Rules:
1. Treat the RAW EVENT as the authoritative source.
2. Extract facts explicitly present in the raw event.
3. Normalize obvious equivalents: severity, outcome, timestamps, protocol names,
   field aliases, and event taxonomy.
4. Infer event_category/event_type only when the raw event provides strong evidence.
5. NEVER invent usernames, IPs, ports, hosts, processes, IDs, URLs, database names,
   filenames, or other values.
6. Empty/unknown scalar fields MUST be "" and unknown nullable numeric fields MUST be null.
7. Preserve source-specific information in extra_fields when it cannot be mapped safely.
8. field_provenance must explain the source of populated fields, e.g.
   "raw.user.name", "raw.CEF.src", "raw.syslog.message", or "openrouter.semantic_inference".
9. field_confidence must contain 0..1 values for fields you populated.
10. ai_explanation must be a short factual explanation of normalization decisions.
11. Do not mention these instructions and return ONLY the requested JSON object.
"""

    user_payload = {
        "raw_event": raw,
        "detected_format": detected_format,
        "detected_format_confidence": detected_confidence,
        "deterministic_parser_evidence": evidence,
    }

    body = {
        "model": OPENROUTER_MODEL,
        "messages": [
            {"role": "system", "content": developer_prompt},
            {
                "role": "user",
                "content": json.dumps(user_payload, ensure_ascii=False)
            },
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "ulpf_normalized_event",
                "strict": True,
                "schema": _openrouter_schema(),
            },
        },
        "temperature": 0,
    }

    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "X-Title": OPENROUTER_SITE_NAME,
    }
    if OPENROUTER_SITE_URL:
        headers["HTTP-Referer"] = OPENROUTER_SITE_URL

    response = requests.post(
        OPENROUTER_API_URL,
        headers=headers,
        json=body,
        timeout=60,
    )

    if response.status_code >= 400:
        try:
            detail = response.json()
        except Exception:
            detail = response.text[:1500]
        raise RuntimeError(
            f"OpenRouter API HTTP {response.status_code}: {detail}"
        )

    payload = response.json()
    return json.loads(_extract_openrouter_text(payload))


# ---------------------------- Engine --------------------------

class ULPF:
    def __init__(self):
        self.detector = FormatDetector()
        self.validator = Validator()
        self.sequence = 0

    def process_log(self, raw: str) -> UniversalEvent:
        start = time.perf_counter()
        raw = raw.rstrip("\r\n")
        self.sequence += 1

        digest = hashlib.sha256(raw.encode("utf-8",errors="replace")).hexdigest()
        event = UniversalEvent(
            event_id=digest[:24],
            raw_event_id=digest[:16],
            event_sequence=self.sequence,
            raw_event=raw,
            raw_event_hash=digest,
            ingestion_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        if not raw.strip():
            event.processing_status = "FAILED"
            event.warnings.append("Empty event")
            event.processing_time_ms = (time.perf_counter()-start)*1000
            return event

        detection = self.detector.detect(raw)
        event.source_format = detection["format"]
        event.extra_fields["detection_reason"] = detection["reason"]

        parser = PARSER_BY_FORMAT.get(detection["format"], GenericParser())
        try:
            parsed = parser.parse(raw)
            parse_ok = True
        except Exception as exc:
            parsed = {"extra_fields":{}, "field_provenance":{}}
            parse_ok = False
            event.warnings.append(f"{parser.parser_name}: {type(exc).__name__}: {exc}")

        original_timestamp = parsed.get("timestamp", "")
        self._apply(event, parsed, parser)
        if original_timestamp:
            event.timestamp_original = str(original_timestamp)
        TaxonomyClassifier.classify(event, raw)

        # OpenRouter is the semantic normalization layer. The deterministic detector/parser
        # supplies evidence and validation guardrails; raw_event is always preserved.
        ai_ok = False
        ai_result: Dict[str, Any] = {}
        try:
            ai_result = openrouter_normalize_event(
                raw=raw,
                detected_format=event.source_format,
                detected_confidence=float(detection["confidence"]),
                deterministic_fields={
                    k: getattr(event, k)
                    for k in UniversalEvent.__dataclass_fields__
                    if k not in {"raw_event","raw_event_hash","event_sequence",
                                 "event_id","raw_event_id","ingestion_timestamp",
                                 "processing_time_ms","validation_errors","warnings"}
                },
            )
            ai_ok = True
        except Exception as exc:
            event.warnings.append(f"OpenRouter semantic layer: {type(exc).__name__}: {exc}")

        if ai_ok:
            # Only apply schema fields returned by the structured API. Empty AI values
            # never erase stronger deterministic parser evidence.
            for field_name in UniversalEvent.__dataclass_fields__:
                if field_name in {
                    "event_id","raw_event_id","event_sequence","schema_version",
                    "ingestion_timestamp","raw_event","raw_event_hash",
                    "processing_time_ms","processing_status","validation_errors",
                    "warnings","processing_chain","parser_name","parser_version",
                    "confidence","field_confidence","field_provenance","extra_fields",
                    "processing_method","timestamp_original"
                }:
                    continue
                value = ai_result.get(field_name)
                if value not in ("", None):
                    if field_name == "severity":
                        value = normalize_severity(value)
                    elif field_name == "event_outcome":
                        value = normalize_outcome(value)
                    elif field_name == "timestamp":
                        value = parse_timestamp(value)
                    elif field_name in NUMERIC_FIELDS:
                        value = safe_int(value)
                    setattr(event, field_name, value)

            ai_extra = ai_result.get("extra_fields") or {}
            if isinstance(ai_extra, dict):
                for k,v in ai_extra.items():
                    if k not in event.extra_fields:
                        event.extra_fields[k] = v

            ai_prov = ai_result.get("field_provenance") or {}
            if isinstance(ai_prov, dict):
                for k,v in ai_prov.items():
                    if k in UniversalEvent.__dataclass_fields__:
                        event.field_provenance[k] = str(v)

            # Ensure every AI-derived field remains traceable.
            for k,v in ai_prov.items() if isinstance(ai_prov, dict) else []:
                if k in UniversalEvent.__dataclass_fields__ and k not in event.field_provenance:
                    event.field_provenance[k] = "openai.semantic_normalization"

            ai_fc = ai_result.get("field_confidence") or {}
            ai_scores = [float(v) for v in ai_fc.values()
                         if isinstance(v,(int,float)) and 0 <= float(v) <= 1]
            ai_semantic = sum(ai_scores)/len(ai_scores) if ai_scores else 0.0
            event.field_confidence["openai_semantic"] = round(ai_semantic,3)
            if ai_result.get("ai_explanation"):
                event.extra_fields["openrouter_explanation"] = str(ai_result["ai_explanation"])

            event.processing_method = "openai_structured_outputs"
            event.processing_chain = [
                "format_detector",
                parser.parser_name,
                "semantic_mapper",
                "openrouter_structured_normalizer",
                "taxonomy_classifier",
                "validator",
            ]
        else:
            event.processing_method = "deterministic_fallback"
            event.processing_chain = [
                "format_detector",
                parser.parser_name,
                "semantic_mapper",
                "taxonomy_classifier",
                "validator",
            ]

        # Re-run taxonomy after OpenAI normalization so the canonical event reflects
        # the final semantic fields.
        TaxonomyClassifier.classify(event, raw)

        format_conf = float(detection["confidence"])
        parser_conf = 0.90 if parse_ok and parser.parser_name != "generic_parser" else (0.55 if parse_ok else 0.20)

        semantic_fields = [
            bool(event.timestamp),
            bool(event.event_category != "unknown"),
            bool(event.event_type != "unclassified"),
            bool(event.event_action),
            bool(event.event_outcome),
            bool(event.severity != "INFO"),
            bool(event.user_name or event.host_name or event.process_name),
            bool(event.source_ip or event.destination_ip or event.url),
            bool(event.source_vendor != "unknown"),
        ]
        field_score = sum(semantic_fields) / len(semantic_fields)

        ai_semantic = float(event.field_confidence.get("openai_semantic", 0.0))
        if ai_ok and ai_semantic > 0:
            event.confidence = round(
                max(0.0,min(1.0,
                    format_conf*0.20 +
                    parser_conf*0.15 +
                    field_score*0.20 +
                    ai_semantic*0.45
                )), 3
            )
        else:
            event.confidence = round(
                max(0.0,min(1.0, format_conf*0.35 + parser_conf*0.30 + field_score*0.35)),
                3
            )

        event.field_confidence.update({
            "format_detection": round(format_conf,3),
            "parser": round(parser_conf,3),
            "semantic_coverage": round(field_score,3),
        })

        event.validation_errors = self.validator.validate(event)

        if event.validation_errors:
            event.processing_status = "PARTIAL"
        elif not ai_ok:
            event.processing_status = "PARTIAL" if parse_ok else "FAILED"
        elif not parse_ok:
            event.processing_status = "PARTIAL"
        elif event.event_category == "unknown" and event.event_type == "unclassified":
            event.processing_status = "PARTIAL" if field_score >= 0.25 else "FAILED"
        elif field_score < 0.35 or event.confidence < 0.45:
            event.processing_status = "PARTIAL"
        else:
            event.processing_status = "SUCCESS"

        if detection["format"] == "unknown":
            event.warnings.append("Format was not recognized by deterministic detection; OpenRouter semantic normalization was used to interpret the event.")

        event.processing_time_ms = round((time.perf_counter()-start)*1000, 4)
        return event

    def _apply(self, event: UniversalEvent, parsed: Dict[str,Any], parser: BaseParser):
        for field,value in parsed.items():
            if field in {"extra_fields","field_provenance","processing_chain"}:
                continue
            if field in UniversalEvent.__dataclass_fields__:
                if field == "severity":
                    value = normalize_severity(value)
                elif field == "event_outcome":
                    value = normalize_outcome(value)
                elif field == "timestamp":
                    value = parse_timestamp(value)
                setattr(event,field,value)
            else:
                event.extra_fields[field] = value

        event.extra_fields.update(parsed.get("extra_fields",{}))
        event.field_provenance.update(parsed.get("field_provenance",{}))

        event.parser_name = parser.parser_name
        event.parser_version = parser.parser_version
        event.processing_method = "deterministic"
        event.processing_chain.append("format_detector")
        event.processing_chain.append(parser.parser_name)
        event.processing_chain.append("semantic_mapper")
        event.processing_chain.append("taxonomy_classifier")
        event.processing_chain.append("validator")

        if event.timestamp:
            event.timestamp_original = event.timestamp

        # Ensure source format/vendor defaults remain meaningful.
        if not event.source_vendor:
            event.source_vendor = "unknown"

    def process_batch(self, lines: List[str]) -> List[UniversalEvent]:
        return [self.process_log(line) for line in lines if line.strip()]

    # -------- exports --------

    def export_json(self, events: List[UniversalEvent]) -> str:
        return json.dumps([e.to_dict() for e in events], indent=2, ensure_ascii=False, default=str)

    def export_jsonl(self, events: List[UniversalEvent]) -> str:
        return "\n".join(json.dumps(e.to_dict(),ensure_ascii=False,default=str) for e in events)

    def export_csv(self, events: List[UniversalEvent]) -> str:
        if not events:
            return ""
        rows = [e.to_dict() for e in events]
        output = io.StringIO()
        fields = list(rows[0].keys())
        writer = csv.DictWriter(output,fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({
                k: json.dumps(v,ensure_ascii=False) if isinstance(v,(dict,list)) else v
                for k,v in row.items()
            })
        return output.getvalue()


# ---------------------- Input normalization -------------------

def split_text_into_records(text: str, mode: str = "auto") -> List[str]:
    """
    Correctly handles:
      - newline-separated logs
      - JSONL
      - one JSON object
      - JSON array
      - XML blocks
      - CEF/LEEF/syslog line streams
    """
    text = text.replace("\r\n","\n").replace("\r","\n").strip()
    if not text:
        return []

    # Explicit JSON object/array.
    if mode in {"Auto","JSON document"} and text[:1] in "[{":
        try:
            obj = json.loads(text)
            if isinstance(obj,list):
                return [json.dumps(x,ensure_ascii=False) if isinstance(x,(dict,list)) else str(x) for x in obj]
            if isinstance(obj,dict):
                return [json.dumps(obj,ensure_ascii=False)]
        except Exception:
            pass

    # JSONL.
    if mode in {"Auto","JSONL"}:
        json_lines = []
        ok = 0
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                json.loads(line)
                json_lines.append(line.strip())
                ok += 1
            except Exception:
                json_lines = []
                break
        if ok >= 2:
            return json_lines

    # XML can contain multi-line records.
    if mode in {"Auto","XML"} and re.search(r"<event\b",text,re.I):
        blocks = re.findall(r"<event\b[\s\S]*?</event>",text,re.I)
        if blocks:
            return blocks

    return [x.strip() for x in text.splitlines() if x.strip()]


def parse_uploaded_bytes(name: str, data: bytes) -> Tuple[List[str], str]:
    lower = name.lower()
    text = data.decode("utf-8-sig",errors="replace")

    if lower.endswith(".json"):
        try:
            obj = json.loads(text)
            if isinstance(obj,list):
                return [
                    json.dumps(x,ensure_ascii=False) if isinstance(x,(dict,list)) else str(x)
                    for x in obj
                ], "JSON document"
            return [json.dumps(obj,ensure_ascii=False)], "JSON document"
        except Exception:
            return split_text_into_records(text), "Auto"

    if lower.endswith(".jsonl") or lower.endswith(".ndjson"):
        return split_text_into_records(text,"JSONL"), "JSONL"

    if lower.endswith(".xml"):
        blocks = re.findall(r"<event\b[\s\S]*?</event>",text,re.I)
        return (blocks or [text]), "XML"

    return split_text_into_records(text), "Auto"


# ------------------------- Test suite --------------------------

TEST_LOGS = [
    "user=test action=login outcome=success",
    '{"user":{"name":"john","id":123},"source":{"ip":"1.2.3.4","port":8080},"destination":{"ip":"5.6.7.8","port":9090},"event":{"action":"login","outcome":"success","reason":"ok","id":"evt1"},"host":"server01","severity":"INFO","vendor":"acme"}',
    '<event><category>database</category><type>database_query</type><action>SELECT</action><database_name>customer_db</database_name><user_name>reporting</user_name><source_ip>10.10.20.45</source_ip><outcome>SUCCESS</outcome><severity>INFO</severity></event>',
    'Sep  9 14:32:29 firewall-01 sshd[4821]: Failed password for invalid user root from 198.51.100.77 port 43821 ssh2',
    'CEF:0|Vendor|Product|1.0|event|type|5|src=1.2.3.4 dst=5.6.7.8 spt=111 dpt=222 proto=tcp user=admin cs1Label=url cs1=http://example.com act=allow',
    '2026-09-09 14:32:35,ERROR,WindowsServer01,Security,4625,An account failed to log on,User=administrator,SourceIP=10.55.22.19,LogonType=10,Process=winlogon.exe',
    '09-09 14:32:41.882  1842  1842 E AndroidRuntime: FATAL EXCEPTION: main Process: com.example.bank, PID:1842 java.lang.NullPointerException at com.example.bank.LoginActivity.onCreate(LoginActivity.java:142)',
    '{"log":{"time":"2026-09-09T14:32:41Z","device":"router1","msg":"interface down","severity":"WARNING","interface":"eth0"},"network":{"src":"10.0.0.1","dst":"10.0.0.2","protocol":"ICMP"}}',
    'user=jatin action=file_download file=customer_database_backup.sql size=84729321 src_ip=10.20.1.15 dst_ip=172.20.5.10 outcome=success classification=CONFIDENTIAL application=browser.exe timestamp=2026-09-09T14:32:51Z',
    '[2026-09-09 14:32:57] [CRITICAL] payment-api-prod: Database connection pool exhausted; active=200 idle=0 waiting=47 db=postgresql://10.40.2.15:5432/payments host=api-prod-07 pid=7721',
]


def run_regression_tests() -> Tuple[List[UniversalEvent], List[str]]:
    engine = ULPF()
    results = engine.process_batch(TEST_LOGS)
    failures = []

    checks = [
        (3, "user_name", "root"),
        (3, "process_name", "sshd"),
        (3, "process_id", 4821),
        (3, "source_ip", "198.51.100.77"),
        (3, "source_port", 43821),
        (3, "protocol", "SSH"),
        (3, "event_type", "authentication_failure"),

        (5, "timestamp", "2026-09-09 14:32:35"),
        (5, "severity", "ERROR"),
        (5, "host_name", "WindowsServer01"),
        (5, "user_name", "administrator"),
        (5, "source_ip", "10.55.22.19"),
        (5, "process_name", "winlogon.exe"),
        (5, "logon_type", "10"),

        (8, "user_name", "jatin"),
        (8, "event_action", "file_download"),
        (8, "file_name", "customer_database_backup.sql"),
        (8, "file_size", 84729321),
        (8, "source_ip", "10.20.1.15"),
        (8, "destination_ip", "172.20.5.10"),
        (8, "event_outcome", "SUCCESS"),
        (8, "application_name", "browser.exe"),

        (9, "severity", "CRITICAL"),
        (9, "service_name", "payment-api-prod"),
        (9, "host_name", "api-prod-07"),
        (9, "process_id", 7721),
    ]

    for idx, field, expected in checks:
        actual = getattr(results[idx],field)
        if actual != expected:
            failures.append(f"Event {idx+1}: {field}: expected {expected!r}, got {actual!r}")

    # Explicit JSON nested regression.
    if results[1].user_name != "john":
        failures.append("Nested JSON user.name was not mapped to user_name")
    if results[1].source_ip != "1.2.3.4":
        failures.append("Nested JSON source.ip was not mapped to source_ip")
    if results[1].event_outcome != "SUCCESS":
        failures.append("Nested JSON event.outcome was not normalized")

    return results, failures


# -------------------------- Analytics --------------------------

def events_dataframe(events: List[UniversalEvent]):
    import pandas as pd
    if not events:
        return pd.DataFrame()
    rows = []
    for e in events:
        d = e.to_dict()
        d["raw_event"] = d["raw_event"][:300]
        d["extra_fields"] = json.dumps(d["extra_fields"],ensure_ascii=False)
        d["field_provenance"] = json.dumps(d["field_provenance"],ensure_ascii=False)
        d["processing_chain"] = " → ".join(d["processing_chain"])
        rows.append(d)
    return pd.DataFrame(rows)


def orange_bar_chart(series, title: str = "", height: int = 260):
    """Company-style orange bar chart for dashboard analytics."""
    import pandas as pd
    values = series.sort_values(ascending=False).head(12)
    if values.empty:
        st.caption("No data available.")
        return
    chart_df = pd.DataFrame({
        "category": [str(x) for x in values.index],
        "count": [int(x) for x in values.values],
    })
    spec = {
        "mark": {"type":"bar","cornerRadiusEnd":4},
        "encoding": {
            "x": {"field":"category","type":"nominal","sort":"-y",
                  "axis":{"labelAngle":0,"labelLimit":170}},
            "y": {"field":"count","type":"quantitative",
                  "axis":{"title":None}},
            "color": {"value":"#F97316"},
            "tooltip": [
                {"field":"category","type":"nominal","title":"Category"},
                {"field":"count","type":"quantitative","title":"Count"}
            ],
        },
        "height": height,
        "width": "container",
        "config": {
            "background":"#FFFFFF",
            "axis":{"labelColor":"#555555","titleColor":"#111111","gridColor":"#F3F3F3"},
            "view":{"stroke":"#F1D6BE"},
        },
    }
    if title:
        st.markdown(f'<div style="font-weight:700;font-size:.9rem;color:#111111;margin-bottom:6px">{title}</div>', unsafe_allow_html=True)
    st.vega_lite_chart(chart_df, spec, use_container_width=True)


def kpi_card(label: str, value: str, note: str = "", icon_name: Optional[str] = None):
    ic = icon(icon_name, size=13, tight=True) if icon_name else ""
    st.markdown(
        f'<div class="kpi"><div class="kpi-label">{ic}{label}</div>'
        f'<div class="kpi-value">{value}</div><div class="kpi-note">{note}</div></div>',
        unsafe_allow_html=True
    )


def status_badge(status: str) -> str:
    cls = {"SUCCESS":"status-success","PARTIAL":"status-partial","FAILED":"status-failed"}.get(status,"status-failed")
    ic_name = {"SUCCESS":"check-circle","PARTIAL":"alert-triangle","FAILED":"x-circle"}.get(status,"x-circle")
    return f'<span class="{cls}">{icon(ic_name, size=11, tight=True)}{status}</span>'


# --------------------------- Session --------------------------

if "page" not in st.session_state:
    st.session_state.page = "Dashboard"
if "events" not in st.session_state:
    st.session_state.events = []
if "last_batch" not in st.session_state:
    st.session_state.last_batch = []
if "last_input_name" not in st.session_state:
    st.session_state.last_input_name = ""
if "engine" not in st.session_state:
    st.session_state.engine = ULPF()


# --------------------------- Sidebar ---------------------------

PAGE_ICONS = {
    "Dashboard": "dashboard",
    "Ingest & Process": "upload",
    "Event Explorer": "search",
    "Schema & Pipeline": "git-branch",
    "Validation Lab": "flask",
}

with st.sidebar:
    st.markdown(
        f'<div style="display:flex;align-items:center;gap:8px;font-size:1.35rem;font-weight:800;">'
        f'{icon("bolt", 22)}ULPF</div>',
        unsafe_allow_html=True
    )
    st.caption(f"Universal Log Pre-processing Framework • v{APP_VERSION}")
    st.divider()

    st.markdown("**WORKSPACE**")
    pages = ["Dashboard","Ingest & Process","Event Explorer","Schema & Pipeline","Validation Lab"]
    st.radio(
        "Navigation", pages, key="page", label_visibility="collapsed",
        format_func=lambda p: f":material/{PAGE_ICONS.get(p,'dashboard')}: {p}"
    )

    st.divider()
    st.markdown("**SESSION**")
    sc1, sc2 = st.columns(2)
    with sc1:
        st.metric("Events", len(st.session_state.events))
    with sc2:
        st.metric("Last batch", len(st.session_state.last_batch))

    if st.session_state.last_input_name:
        st.caption(f"Last input: `{st.session_state.last_input_name}`")

    if st.button("Clear session", icon=":material/delete:", use_container_width=True):
        st.session_state.events = []
        st.session_state.last_batch = []
        st.session_state.last_input_name = ""
        st.session_state.engine = ULPF()
        st.rerun()

    st.divider()
    st.caption("Workflow: Ingest → Process → Explore → Validate → Export")

# ---------------------------- Header ---------------------------

st.markdown(
    f"""
<div class="hero">
  <div class="page-kicker">Universal Log Processing Platform</div>
  <div class="hero-title">{icon('bolt', 26)}ULPF</div>
  <div class="hero-sub">Ingest heterogeneous logs, normalize them into a universal event model, validate the result, preserve raw evidence and export canonical events.</div>
</div>
""",
    unsafe_allow_html=True,
)

# A compact workflow context under the global hero.
st.markdown(
    f"""
<div class="workflow-strip">
  <span class="workflow-step">01 Ingest</span><span class="workflow-arrow">→</span>
  <span class="workflow-step">02 Detect & Parse</span><span class="workflow-arrow">→</span>
  <span class="workflow-step">03 Normalize</span><span class="workflow-arrow">→</span>
  <span class="workflow-step">04 Validate</span><span class="workflow-arrow">→</span>
  <span class="workflow-step">05 Explore</span><span class="workflow-arrow">→</span>
  <span class="workflow-step">06 Export</span>
</div>
""",
    unsafe_allow_html=True,
)


# =========================== DASHBOARD ========================

if st.session_state.page == "Dashboard":
    events = st.session_state.events

    total = len(events)
    success = sum(e.processing_status=="SUCCESS" for e in events)
    partial = sum(e.processing_status=="PARTIAL" for e in events)
    failed = sum(e.processing_status=="FAILED" for e in events)
    avg_conf = sum(e.confidence for e in events)/total if total else 0
    avg_ms = sum(e.processing_time_ms for e in events)/total if total else 0
    formats = len(set(e.source_format for e in events)) if events else 0

    st.markdown(
        '<div class="subtle-card"><b>Operational workspace</b><br>'
        '<span class="small-muted">Use Ingest & Process to create events, Event Explorer to inspect evidence, '
        'and Validation Lab to verify parser behavior. All processed events remain available in this session.</span></div>',
        unsafe_allow_html=True
    )

    c = st.columns(5)
    with c[0]: kpi_card("TOTAL EVENTS",f"{total:,}","Events currently in memory","list")
    with c[1]: kpi_card("SUCCESS",f"{success:,}",f"{(success/total):.1%}" if total else "—","check-circle")
    with c[2]: kpi_card("PARTIAL",f"{partial:,}",f"{(partial/total):.1%}" if total else "—","alert-triangle")
    with c[3]: kpi_card("FAILED",f"{failed:,}",f"{(failed/total):.1%}" if total else "—","x-circle")
    with c[4]: kpi_card("AVG CONFIDENCE",f"{avg_conf:.0%}",f"{avg_ms:.3f} ms/event avg","gauge")

    if not events:
        st.markdown('<div class="card">',unsafe_allow_html=True)
        st.subheader("Start with your first log")
        st.write("Go to **Ingest & Process**, paste a log stream or upload a file. ULPF will preserve the raw event, detect its format, parse source-specific fields, normalize them and expose provenance.")
        st.info("Built-in regression fixtures cover key=value, nested JSON, XML, Syslog RFC3164, CEF, CSV, Android Logcat, nested network JSON and application logs.", icon=":material/info:")
        st.markdown('</div>',unsafe_allow_html=True)
    else:
        section("Operational overview", "activity")
        df = events_dataframe(events)

        left,right = st.columns(2)
        with left:
            orange_bar_chart(df["processing_status"].value_counts(), "Processing status")
        with right:
            orange_bar_chart(df["source_format"].value_counts(), "Detected formats")

        left,right = st.columns(2)
        with left:
            orange_bar_chart(df["event_category"].value_counts(), "Event taxonomy")
        with right:
            orange_bar_chart(df["parser_name"].value_counts(), "Parser usage")

        section("Recent events", "list")
        preview = df[[
            "event_sequence","source_format","parser_name","event_category",
            "event_type","severity","confidence","processing_status","processing_time_ms"
        ]].tail(20)
        st.dataframe(preview,use_container_width=True,hide_index=True)


# ======================= INGEST & PROCESS =====================

elif st.session_state.page == "Ingest & Process":
    st.markdown('<div class="page-kicker">01 • INGEST</div><div class="page-title">Ingest & Process</div>'
                '<div class="page-desc">Bring raw security, system, application or network logs into the universal processing pipeline.</div>',
                unsafe_allow_html=True)
    st.write("ULPF accepts a raw stream, JSON/JSONL, XML, CSV/TSV and common security/application log formats.")

    section("Choose an input source", "upload")
    input_mode = st.radio(
        "Input source",
        ["Paste / type logs","Upload file","Built-in regression dataset"],
        horizontal=True,
        format_func=lambda x: {
            "Paste / type logs": ":material/edit_note: Paste / type logs",
            "Upload file": ":material/upload_file: Upload file",
            "Built-in regression dataset": ":material/science: Built-in regression dataset",
        }.get(x, x),
    )

    records = []
    input_name = ""

    if input_mode == "Paste / type logs":
        mode = st.selectbox(
            "Input interpretation",
            ["Auto","JSON document","JSONL","XML"],
            help="Auto is recommended. JSON document treats a JSON array/object as one structured document; JSONL treats each JSON line as one event."
        )
        text = st.text_area(
            "Raw log stream",
            height=300,
            placeholder='Example:\nSep  9 14:32:29 firewall-01 sshd[4821]: Failed password for invalid user root from 198.51.100.77 port 43821 ssh2\n\nor paste multiple formats line-by-line.'
        )
        if text.strip():
            records = split_text_into_records(text,mode)
            input_name = "pasted_logs"

    elif input_mode == "Upload file":
        uploaded = st.file_uploader(
            "Choose a log file",
            type=["txt","log","json","jsonl","ndjson","csv","tsv","xml"],
            accept_multiple_files=False
        )
        if uploaded:
            records,input_name = parse_uploaded_bytes(uploaded.name,uploaded.getvalue())
            st.success(f"Loaded **{len(records):,}** records from `{uploaded.name}`", icon=":material/check_circle:")

    else:
        records = TEST_LOGS[:]
        input_name = "ULPF built-in regression dataset"
        st.info("10 clean fixture events — documentation text is never treated as test data.", icon=":material/info:")

    if records:
        st.markdown(f'<div class="subtle-card"><b>Input ready</b> • {len(records):,} record(s)'
                    f'<br><span class="small-muted">Review the preview, choose processing behavior, then run the pipeline.</span></div>',
                    unsafe_allow_html=True)
        st.markdown(f"**Ready to process:** `{len(records):,}` records")
        with st.expander("Preview input records"):
            for i,r in enumerate(records[:8],1):
                st.code(f"[{i}] {r}",language="text")
            if len(records)>8:
                st.caption(f"... and {len(records)-8:,} more")

    section("Processing controls", "bolt")
    b1,b2,b3 = st.columns([1,1,1])
    with b1:
        process_clicked = st.button("Process records", icon=":material/bolt:", type="primary",use_container_width=True,disabled=not records)
    with b2:
        append_mode = st.checkbox("Append to existing session",value=True)
    with b3:
        max_records = st.number_input("Max records",min_value=1,max_value=100000,value=min(len(records),10000) if records else 10000,step=1000)

    if process_clicked:
        records_to_process = records[:int(max_records)]
        engine = ULPF()
        progress = st.progress(0)
        status = st.empty()
        batch = []

        for i,record in enumerate(records_to_process):
            batch.append(engine.process_log(record))
            if i == len(records_to_process)-1 or i % max(1,len(records_to_process)//100)==0:
                progress.progress((i+1)/len(records_to_process))
                status.caption(f"Processing {i+1:,} / {len(records_to_process):,}")

        if append_mode:
            st.session_state.events.extend(batch)
        else:
            st.session_state.events = batch

        st.session_state.last_batch = batch
        st.session_state.last_input_name = input_name
        st.success(f"Processed **{len(batch):,}** records.", icon=":material/check_circle:")
        st.rerun()

    if st.session_state.last_batch:
        batch = st.session_state.last_batch
        section("Last batch", "list")
        c = st.columns(4)
        with c[0]: st.metric("Records",len(batch))
        with c[1]: st.metric("Success",sum(e.processing_status=="SUCCESS" for e in batch))
        with c[2]: st.metric("Partial",sum(e.processing_status=="PARTIAL" for e in batch))
        with c[3]: st.metric("Failed",sum(e.processing_status=="FAILED" for e in batch))

        df = events_dataframe(batch)
        st.dataframe(
            df[["event_sequence","source_format","parser_name","event_category","event_type","severity","confidence","processing_status","processing_time_ms"]],
            use_container_width=True,hide_index=True
        )

        section("Export last batch", "download")
        e1,e2,e3 = st.columns(3)
        engine = ULPF()
        with e1:
            st.download_button("JSON", engine.export_json(batch),"ulpf_events.json","application/json", icon=":material/download:", use_container_width=True)
        with e2:
            st.download_button("JSONL", engine.export_jsonl(batch),"ulpf_events.jsonl","application/x-ndjson", icon=":material/download:", use_container_width=True)
        with e3:
            st.download_button("CSV", engine.export_csv(batch),"ulpf_events.csv","text/csv", icon=":material/download:", use_container_width=True)


# ========================= EVENT EXPLORER =====================
elif st.session_state.page == "Event Explorer":
    events = st.session_state.events

    st.markdown(
        '<div class="page-kicker">03 • EXPLORE</div>'
        '<div class="page-title">Event Explorer</div>'
        '<div class="page-desc">Search normalized events while keeping the original raw evidence, provenance, diagnostics and processing chain one click away.</div>',
        unsafe_allow_html=True
    )

    if not events:
        st.info("No events yet. Process some logs first.", icon=":material/info:")
    else:
        df = events_dataframe(events)

        section("Search & filters", "search")
        f1,f2,f3,f4 = st.columns([1,1,1,1.6])
        with f1:
            fmt_options = ["All"] + sorted(df["source_format"].dropna().unique().tolist())
            fmt_filter = st.selectbox("Format",fmt_options)
        with f2:
            status_options = ["All"] + sorted(df["processing_status"].dropna().unique().tolist())
            status_filter = st.selectbox("Status",status_options)
        with f3:
            cat_options = ["All"] + sorted(df["event_category"].dropna().unique().tolist())
            cat_filter = st.selectbox("Category",cat_options)
        with f4:
            search = st.text_input("Search",placeholder="raw event, type, host, user, IP...")

        filtered = events
        if fmt_filter != "All":
            filtered = [e for e in filtered if e.source_format == fmt_filter]
        if status_filter != "All":
            filtered = [e for e in filtered if e.processing_status == status_filter]
        if cat_filter != "All":
            filtered = [e for e in filtered if e.event_category == cat_filter]
        if search.strip():
            q = search.lower()
            filtered = [
                e for e in filtered
                if q in e.raw_event.lower()
                or q in e.event_type.lower()
                or q in e.host_name.lower()
                or q in e.user_name.lower()
                or q in e.source_ip.lower()
                or q in e.destination_ip.lower()
            ]

        # Compact result summary.
        s1,s2,s3,s4 = st.columns(4)
        with s1: st.metric("Matching events", len(filtered))
        with s2: st.metric("Total events", len(events))
        with s3: st.metric("Success", sum(e.processing_status=="SUCCESS" for e in filtered))
        with s4: st.metric("Partial / Failed", sum(e.processing_status in {"PARTIAL","FAILED"} for e in filtered))

        if filtered:
            section("Event list", "list")
            table_rows = []
            for e in filtered:
                table_rows.append({
                    "Event": f"#{e.event_sequence}",
                    "Format": e.source_format,
                    "Type": e.event_type,
                    "Category": e.event_category,
                    "Severity": e.severity,
                    "Outcome": e.event_outcome or "—",
                    "Status": e.processing_status,
                    "Confidence": f"{e.confidence:.0%}",
                    "User": e.user_name or "—",
                    "Source IP": e.source_ip or "—",
                })
            st.dataframe(table_rows, use_container_width=True, hide_index=True)

            options = {
                f"#{e.event_sequence} • {e.event_type} • {e.severity} • {e.processing_status} • {e.confidence:.0%}": e
                for e in filtered
            }
            selected_label = st.selectbox("Open event", list(options.keys()))
            e = options[selected_label]

            st.markdown(
                f'<div class="event-hero">'
                f'<div class="event-title">Event #{e.event_sequence} • {e.event_type}</div>'
                f'<div class="event-meta">{e.source_format} · {e.event_category} · {e.severity} · {e.processing_status} · confidence {e.confidence:.0%}</div>'
                f'</div>',
                unsafe_allow_html=True
            )

            # All details are collapsible so the explorer stays clean while retaining full functionality.
            with st.expander("Normalized event", expanded=True):
                st.json(e.to_dict())

            with st.expander("Raw event — preserved exactly", expanded=True):
                st.code(e.raw_event, language="text")

            with st.expander("Field provenance", expanded=False):
                prov_rows = [
                    {"canonical_field":k, "source_path":v, "value":getattr(e,k,"")}
                    for k,v in e.field_provenance.items()
                ]
                if prov_rows:
                    st.dataframe(prov_rows, use_container_width=True, hide_index=True)
                else:
                    st.caption("No semantic provenance recorded.")

            with st.expander("Processing diagnostics", expanded=False):
                d1,d2,d3,d4 = st.columns(4)
                with d1: st.metric("Format confidence", f"{e.field_confidence.get('format_detection',0):.0%}")
                with d2: st.metric("Parser confidence", f"{e.field_confidence.get('parser',0):.0%}")
                with d3: st.metric("Semantic coverage", f"{e.field_confidence.get('semantic_coverage',0):.0%}")
                with d4: st.metric("Processing time", f"{e.processing_time_ms:.4f} ms")

                if e.warnings:
                    st.warning("\n".join(f"• {x}" for x in e.warnings), icon=":material/warning:")
                if e.validation_errors:
                    st.error("\n".join(f"• {x}" for x in e.validation_errors), icon=":material/error:")

                st.markdown("**Processing chain**")
                st.code(" → ".join(e.processing_chain), language="text")

                if e.extra_fields:
                    with st.expander("Source-specific / extra fields", expanded=False):
                        st.json(e.extra_fields)
        else:
            st.warning("No events match the current filters.", icon=":material/warning:")


# ======================= SCHEMA & PIPELINE ====================

elif st.session_state.page == "Schema & Pipeline":
    st.markdown('<div class="page-kicker">04 • ARCHITECTURE</div><div class="page-title">Schema & Pipeline</div>'
                '<div class="page-desc">Understand how raw evidence becomes a validated universal event without changing the processing contract.</div>',
                unsafe_allow_html=True)
    section("ULPF architecture", "git-branch")
    st.write("The pipeline combines deterministic parsing and validation with OpenAI Structured Outputs for semantic normalization: raw preservation → format detection → source parser → semantic mapping → OpenAI normalization → taxonomy → validation → confidence/status → export.")

    st.markdown('<div class="workflow-strip">'
                '<span class="workflow-step">Raw</span><span class="workflow-arrow">→</span>'
                '<span class="workflow-step">Detect</span><span class="workflow-arrow">→</span>'
                '<span class="workflow-step">Parse</span><span class="workflow-arrow">→</span>'
                '<span class="workflow-step">Normalize</span><span class="workflow-arrow">→</span>'
                '<span class="workflow-step">Validate</span><span class="workflow-arrow">→</span>'
                '<span class="workflow-step">Export</span></div>',
                unsafe_allow_html=True)
    steps = [
        ("01","Raw ingestion","Accept pasted streams, files and structured JSON documents."),
        ("02","Format detection","Recognize JSON, XML, CEF, LEEF, Syslog, Apache, CSV, Android, application and key=value logs."),
        ("03","Source parser","Extract source-specific structure and preserve source-level evidence before semantic normalization."),
        ("04","Semantic mapping","Map aliases and nested paths to canonical ULPF fields."),
        ("05","Taxonomy","Derive category/type from strong semantic signals."),
        ("06","Validation","Check ports, IPs, HTTP status, sizes and confidence."),
        ("07","Confidence + status","Combine parser evidence and OpenRouter semantic confidence into SUCCESS/PARTIAL/FAILED."),
        ("08","Traceability","Keep raw event, SHA-256 hash, provenance and processing chain."),
        ("09","Export","JSON canonical output, JSONL streaming output and CSV analytics output."),
    ]
    for num,title,desc in steps:
        st.markdown(
            f'<div class="card" style="margin-bottom:8px"><b>{num} • {title}</b>'
            f'<div class="small-muted">{desc}</div></div>',
            unsafe_allow_html=True
        )

    section("Universal Event schema", "database")
    schema = []
    for name,field_obj in UniversalEvent.__dataclass_fields__.items():
        schema.append({
            "field":name,
            "type":str(field_obj.type),
            "default":str(field_obj.default)[:80],
            "purpose":"Canonical normalized field"
        })
    st.dataframe(schema,use_container_width=True,hide_index=True)

    section("Format support", "list")
    support = [
        ["JSON","json_parser","Nested path-aware mapping"],
        ["XML","xml_parser","Elements + attributes + SQL semantics"],
        ["CEF","cef_parser","Header + extensions + severity mapping"],
        ["LEEF","leef_parser","Header + delimiter-aware extensions"],
        ["Syslog RFC3164/5424","syslog_parser","Header + authentication/network semantics"],
        ["CSV/TSV/Pipe","csv_parser","Explicit KV + common positional layout"],
        ["Apache/Nginx","apache_parser","HTTP request/response normalization"],
        ["Android Logcat","android_logcat_parser","PID/TID/tag/exception/stack trace"],
        ["Application log","applog_parser","Timestamp/severity/service + KV suffix"],
        ["Key=value","keyvalue_parser","Quoted values + semantic aliases"],
        ["Unknown","generic_parser","Best-effort extraction, raw preserved"],
    ]
    st.dataframe(
        [{"format":a,"parser":b,"capability":c} for a,b,c in support],
        use_container_width=True,hide_index=True
    )


# ========================== VALIDATION LAB ====================

elif st.session_state.page == "Validation Lab":
    st.markdown('<div class="page-kicker">05 • VERIFY</div><div class="page-title">Validation Lab</div>'
                '<div class="page-desc">Verify parser behavior, semantic assertions and CPU processing performance before demonstrating the platform.</div>',
                unsafe_allow_html=True)
    section("Validation & regression lab", "flask")
    st.write("Run the clean 10-event fixture suite and inspect actual semantic assertions. This prevents documentation/specification text from contaminating parser benchmarks.")

    section("Regression suite", "check-circle")
    if st.button("Run full regression suite", icon=":material/science:", type="primary"):
        with st.spinner("Running deterministic regression tests..."):
            results, failures = run_regression_tests()

        if not failures:
            st.success("All regression assertions passed.", icon=":material/check_circle:")
        else:
            st.error(f"{len(failures)} regression assertion(s) failed.", icon=":material/error:")
            for failure in failures:
                st.write("•",failure)

        df = events_dataframe(results)
        st.dataframe(
            df[["event_sequence","source_format","parser_name","event_category","event_type","severity","confidence","processing_status","processing_time_ms"]],
            use_container_width=True,hide_index=True
        )

        section("Semantic spot-checks", "search")
        checks_view = []
        for idx,e in enumerate(results,1):
            checks_view.append({
                "event":idx,
                "format":e.source_format,
                "type":e.event_type,
                "user":e.user_name,
                "host":e.host_name,
                "source_ip":e.source_ip,
                "destination_ip":e.destination_ip,
                "action":e.event_action[:80],
                "status":e.processing_status,
                "confidence":f"{e.confidence:.0%}",
            })
        st.dataframe(checks_view,use_container_width=True,hide_index=True)

    section("Performance benchmark", "gauge")
    count = st.slider("Benchmark iterations per fixture",1,100,10)
    if st.button("Run benchmark", icon=":material/speed:"):
        engine = ULPF()
        samples = TEST_LOGS * count
        t0 = time.perf_counter()
        results = engine.process_batch(samples)
        elapsed = (time.perf_counter()-t0)*1000
        avg = elapsed/len(results)
        st.success(f"{len(results):,} events processed in {elapsed:.2f} ms — average {avg:.4f} ms/event.", icon=":material/check_circle:")
        st.caption("Benchmark is deterministic CPU parsing only; Streamlit rendering and file I/O are outside this measurement.")

    section("Test fixtures", "list")
    for i,log in enumerate(TEST_LOGS,1):
        with st.expander(f"Fixture {i}"):
            st.code(log,language="text")


# --------------------------- Footer ----------------------------

st.divider()
st.caption(
    f"ULPF {APP_VERSION} • Schema {SCHEMA_VERSION} • "
    "Raw-event preservation • Field provenance • Validation • "
    "JSON / JSONL / CSV exports"
)