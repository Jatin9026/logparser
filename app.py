import streamlit as st
import json
import csv
import io
import os
import re
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

# ============================================================
# ULPF — Universal Log Pre-processing Framework
# ============================================================

APP_VERSION = "4.3.0"
SCHEMA_VERSION = "4.0.0"

# --------------------------------------------------------------
# SECURITY NOTE: the API key is no longer hardcoded in source.
# Provide it via Streamlit secrets (.streamlit/secrets.toml):
#     OPENROUTER_API_KEY = "sk-or-v1-..."
# or as an environment variable OPENROUTER_API_KEY.
# --------------------------------------------------------------
def _get_key() -> str:
    try:
        if "OPENROUTER_API_KEY" in st.secrets:
            return st.secrets["OPENROUTER_API_KEY"]
    except Exception:
        pass
    return os.environ.get("OPENROUTER_API_KEY", "")


_API_URL = "https://openrouter.ai/api/v1/chat/completions"
_MODEL = "qwen/qwen-2.5-72b-instruct"
_MAX_WORKERS = 8


st.set_page_config(
    page_title="ULPF • Universal Log Pre-processing Framework",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------- Universal Event -----------------------

@dataclass
class UniversalEvent:
    event_id: str = ""
    raw_event_id: str = ""
    event_sequence: int = 0
    schema_version: str = SCHEMA_VERSION
    timestamp: str = ""
    ingestion_timestamp: str = ""
    event_category: str = "unknown"
    event_type: str = "unclassified"
    event_action: str = ""
    event_outcome: str = ""
    severity: str = "INFO"
    source_ip: str = ""
    source_port: Optional[int] = None
    destination_ip: str = ""
    destination_port: Optional[int] = None
    protocol: str = ""
    user_name: str = ""
    user_id: str = ""
    host_name: str = ""
    process_name: str = ""
    process_id: Optional[int] = None
    application_name: str = ""
    service_name: str = ""
    url: str = ""
    http_method: str = ""
    http_status: Optional[int] = None
    database_name: str = ""
    query_type: str = ""
    file_name: str = ""
    exception_type: str = ""
    source_vendor: str = "unknown"
    source_product: str = ""
    source_format: str = "unparsed"
    parser_name: str = ""
    parser_version: str = "4.3"
    raw_event: str = ""
    raw_event_hash: str = ""
    processing_method: str = "none"
    processing_chain: List[str] = field(default_factory=list)
    confidence: float = 0.0
    field_confidence: Dict[str, float] = field(default_factory=dict)
    field_provenance: Dict[str, str] = field(default_factory=dict)
    processing_time_ms: float = 0.0
    processing_status: str = "FAILED"
    warnings: List[str] = field(default_factory=list)
    extra_fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


NON_OVERWRITABLE_FIELDS = {
    "event_id", "raw_event_id", "event_sequence", "schema_version",
    "ingestion_timestamp", "raw_event", "raw_event_hash",
    "processing_time_ms", "processing_status", "warnings",
    "processing_chain", "parser_name", "parser_version",
    "confidence", "field_confidence", "field_provenance",
    "extra_fields", "processing_method",
}

# --------------------------- AI Parser ---------------------------

class AIParser:
    """Parses a raw log line into structured fields. Returns (result_dict_or_None, error_message)."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._session = requests.Session()

    def parse(self, raw: str) -> Tuple[Optional[Dict[str, Any]], str]:
        if not self.api_key:
            return None, "not configured"

        prompt = f"""You are an expert log parser. Analyze this log and extract ALL meaningful fields.

LOG: {raw}

Return ONLY valid JSON with these fields:
{{
    "timestamp": "Event time or empty string",
    "event_category": "security/network/database/application/system/authentication/other",
    "event_type": "Specific type like login/access/transaction/query/error/warning",
    "event_action": "What happened (short)",
    "event_outcome": "SUCCESS/FAILURE/PARTIAL or empty",
    "severity": "DEBUG/INFO/WARNING/ERROR/CRITICAL",
    "source_ip": "IP or empty",
    "destination_ip": "IP or empty",
    "source_port": null or integer,
    "destination_port": null or integer,
    "protocol": "TCP/UDP/HTTP/HTTPS/SSH or empty",
    "user_name": "Username or empty",
    "host_name": "Hostname/device or empty",
    "process_name": "Process name or empty",
    "process_id": null or integer,
    "service_name": "Service name or empty",
    "file_name": "File name or empty",
    "database_name": "Database name or empty",
    "source_vendor": "Vendor or unknown",
    "source_format": "json/syslog/cef/csv/key_value/custom",
    "confidence": 0.0 to 1.0,
    "extra_fields": {{"key": "value"}}
}}

Rules:
- Use "" for missing text fields
- Use null for missing numeric fields
- Give confidence at least 0.7 if you identify any fields
- Return ONLY the JSON, no other text, no markdown code fences
"""

        last_error = ""
        for attempt in range(3):
            try:
                response = self._session.post(
                    _API_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": _MODEL,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.1,
                        "max_tokens": 900,
                    },
                    timeout=20,
                )

                if response.status_code == 200:
                    result = response.json()
                    choices = result.get("choices", [])
                    if not choices:
                        last_error = "empty response"
                        break
                    content = choices[0]["message"]["content"]
                    parsed = self._extract_json(content)
                    if parsed is not None:
                        return parsed, ""
                    last_error = "unparsable response"
                    break

                elif response.status_code == 401:
                    return None, "unauthorized"
                elif response.status_code == 429:
                    last_error = "rate limited"
                    time.sleep(0.8 * (attempt + 1))
                    continue
                elif response.status_code >= 500:
                    last_error = f"server error {response.status_code}"
                    time.sleep(0.6 * (attempt + 1))
                    continue
                else:
                    last_error = f"HTTP {response.status_code}"
                    break

            except requests.exceptions.Timeout:
                last_error = "timed out"
                continue
            except requests.exceptions.ConnectionError as e:
                last_error = "connection error"
                continue
            except Exception as e:
                last_error = "unexpected error"
                break

        return None, last_error or "unknown failure"

    @staticmethod
    def _extract_json(content: str) -> Optional[Dict[str, Any]]:
        if not content:
            return None
        text = content.strip()
        fence_match = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
        if fence_match:
            text = fence_match.group(1).strip()
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        candidate = text if text.startswith("{") else (brace_match.group(0) if brace_match else None)
        if not candidate:
            return None
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            return None


# --------------------- Heuristic (offline) Parser ---------------------

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
KV_RE = re.compile(r"(\w[\w\-]*)=(\"[^\"]*\"|'[^']*'|\S+)")
SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[\w\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
CEF_RE = re.compile(r"^CEF:\d\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$")
SEVERITY_WORDS = {
    "CRITICAL": ["critical", "fatal", "emerg"],
    "ERROR": ["error", "fail", "failed", "denied", "reject"],
    "WARNING": ["warn", "warning"],
    "DEBUG": ["debug", "trace"],
}


def guess_severity(text: str) -> str:
    lowered = text.lower()
    for level, words in SEVERITY_WORDS.items():
        if any(w in lowered for w in words):
            return level
    return "INFO"


def heuristic_parse(raw: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "event_action": raw[:300],
        "severity": guess_severity(raw),
        "source_format": "custom",
        "confidence": 0.35,
        "extra_fields": {},
    }

    stripped = raw.strip()

    if stripped.startswith("{") or stripped.startswith("["):
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                result["source_format"] = "json"
                result["confidence"] = 0.6
                flat = _flatten(obj)
                result["extra_fields"] = flat
                _map_common_keys(flat, result)
                return result
        except json.JSONDecodeError:
            pass

    cef = CEF_RE.match(stripped)
    if cef:
        vendor, product, version, sig_id, name, severity, ext = cef.groups()
        result["source_format"] = "cef"
        result["source_vendor"] = vendor or "unknown"
        result["source_product"] = product or ""
        result["event_action"] = name or result["event_action"]
        result["confidence"] = 0.55
        kv = dict(KV_RE.findall(ext))
        result["extra_fields"] = kv
        _map_cef_keys(kv, result)
        return result

    sl = SYSLOG_RE.match(stripped)
    if sl:
        g = sl.groupdict()
        result["source_format"] = "syslog"
        result["timestamp"] = g.get("ts", "")
        result["host_name"] = g.get("host", "")
        result["process_name"] = g.get("proc", "")
        if g.get("pid"):
            try:
                result["process_id"] = int(g["pid"])
            except ValueError:
                pass
        result["event_action"] = g.get("msg", "")[:300]
        result["confidence"] = 0.55
        ips = IP_RE.findall(g.get("msg", ""))
        if ips:
            result["source_ip"] = ips[0]
        if "failed password" in stripped.lower() or "authentication failure" in stripped.lower():
            result["event_category"] = "authentication"
            result["event_type"] = "login"
            result["event_outcome"] = "FAILURE"
        return result

    kv_pairs = dict(KV_RE.findall(stripped))
    if kv_pairs:
        result["source_format"] = "key_value"
        result["confidence"] = 0.5
        result["extra_fields"] = kv_pairs
        _map_common_keys(kv_pairs, result)
        return result

    ips = IP_RE.findall(stripped)
    if ips:
        result["source_ip"] = ips[0]
        result["confidence"] = 0.4

    return result


def _flatten(obj: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    flat = {}
    for k, v in obj.items():
        key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
        if isinstance(v, dict):
            flat.update(_flatten(v, key))
        else:
            flat[key] = v
    return flat


def _map_common_keys(flat: Dict[str, Any], result: Dict[str, Any]) -> None:
    aliases = {
        "user_name": ["user", "username", "user.name", "usr"],
        "source_ip": ["src", "source_ip", "src_ip", "source.ip", "srcip", "ip"],
        "destination_ip": ["dst", "destination_ip", "dst_ip", "destination.ip", "dstip"],
        "host_name": ["host", "hostname", "host.name"],
        "event_action": ["action", "event.action", "act", "msg", "message"],
        "event_outcome": ["outcome", "event.outcome", "status", "result"],
        "process_name": ["process", "proc", "process.name"],
        "database_name": ["database", "db", "database.name"],
        "protocol": ["proto", "protocol"],
        "file_name": ["file", "filename", "file.name"],
    }
    lower_flat = {k.lower(): v for k, v in flat.items()}
    for target, keys in aliases.items():
        for k in keys:
            if k in lower_flat and lower_flat[k] not in (None, ""):
                result[target] = str(lower_flat[k]).strip("\"'")
                break


def _map_cef_keys(kv: Dict[str, str], result: Dict[str, Any]) -> None:
    cef_map = {
        "src": "source_ip", "dst": "destination_ip", "spt": "source_port",
        "dpt": "destination_port", "proto": "protocol", "user": "user_name",
        "dhost": "host_name", "fname": "file_name",
    }
    for k, target in cef_map.items():
        if k in kv:
            val = kv[k].strip("\"'")
            if target in {"source_port", "destination_port"}:
                try:
                    result[target] = int(val)
                except ValueError:
                    pass
            else:
                result[target] = val


# ---------------------------- Engine --------------------------

class ULPF:
    """
    Normalizes arbitrary log lines onto the Universal Event Schema.
    Uses a primary parser for high-accuracy field extraction, with an
    offline heuristic parser as a fallback so processing never stalls.
    """

    def __init__(self, api_key: str = ""):
        self.parser = AIParser(api_key)
        self.sequence = 0
        self.enabled = bool(api_key)

    def process_log(self, raw: str) -> UniversalEvent:
        raw = raw.strip()
        result, error = (None, "disabled") if not self.enabled else self.parser.parse(raw)
        return self._finalize(raw, result, error)

    def process_batch(self, lines: List[str], on_progress=None) -> List[UniversalEvent]:
        """Processes many lines concurrently. Identical lines are parsed once and reused."""
        lines = [l.strip() for l in lines if l.strip()]
        if not lines:
            return []

        cache: Dict[str, Tuple[Optional[Dict[str, Any]], str]] = {}

        if self.enabled:
            unique_raws = list(dict.fromkeys(lines))
            done = 0
            total = len(unique_raws)
            with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, total)) as pool:
                future_map = {pool.submit(self.parser.parse, r): r for r in unique_raws}
                for future in as_completed(future_map):
                    raw = future_map[future]
                    try:
                        cache[raw] = future.result()
                    except Exception as e:
                        cache[raw] = (None, "unexpected error")
                    done += 1
                    if on_progress:
                        on_progress(done, total)

        events = []
        for line in lines:
            result, error = cache.get(line, (None, "disabled"))
            events.append(self._finalize(line, result, error))
        return events

    def _finalize(self, raw: str, result: Optional[Dict[str, Any]], error: str) -> UniversalEvent:
        start = time.perf_counter()
        self.sequence += 1

        digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
        event = UniversalEvent(
            event_id=digest[:24],
            raw_event_id=digest[:16],
            event_sequence=self.sequence,
            raw_event=raw,
            raw_event_hash=digest,
            ingestion_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        if not raw:
            event.processing_status = "FAILED"
            event.warnings.append("Empty event")
            return event

        if result:
            self._apply_result(event, result)
            event.processing_method = "smart"
            event.processing_chain = ["smart_parser"]
            event.parser_name = "smart_parser"
        else:
            if self.enabled:
                event.warnings.append(f"Primary parsing unavailable ({error}); used fallback")
            heuristic_result = heuristic_parse(raw)
            self._apply_result(event, heuristic_result)
            event.processing_method = "fallback"
            event.processing_chain = ["fallback_parser"]
            event.parser_name = "fallback_parser"

        if event.confidence >= 0.7:
            event.processing_status = "SUCCESS"
        elif event.confidence >= 0.4:
            event.processing_status = "PARTIAL"
        else:
            event.processing_status = "FAILED"

        event.processing_time_ms = round((time.perf_counter() - start) * 1000, 2)
        return event

    @staticmethod
    def _apply_result(event: UniversalEvent, result: Dict[str, Any]) -> None:
        for field_name in UniversalEvent.__dataclass_fields__:
            if field_name in NON_OVERWRITABLE_FIELDS:
                continue
            value = result.get(field_name)
            if value not in ("", None):
                if field_name in {"source_port", "destination_port", "process_id", "http_status"}:
                    try:
                        value = int(value)
                    except (TypeError, ValueError):
                        value = None
                if value is not None:
                    setattr(event, field_name, value)

        extra = result.get("extra_fields", {})
        if isinstance(extra, dict):
            event.extra_fields.update(extra)

        try:
            event.confidence = round(float(result.get("confidence", 0.5)), 2)
        except (TypeError, ValueError):
            event.confidence = 0.5

        if result.get("source_format"):
            event.source_format = result["source_format"]

    def export_json(self, events: List[UniversalEvent]) -> str:
        return json.dumps([e.to_dict() for e in events], indent=2, default=str)

    def export_jsonl(self, events: List[UniversalEvent]) -> str:
        return "\n".join(json.dumps(e.to_dict(), default=str) for e in events)

    def export_csv(self, events: List[UniversalEvent]) -> str:
        if not events:
            return ""
        rows = [e.to_dict() for e in events]
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in row.items()})
        return output.getvalue()


# ---------------------- Input handling -------------------

def split_text_into_records(text: str) -> List[str]:
    text = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        return []
    return [x.strip() for x in text.splitlines() if x.strip()]


def parse_uploaded_bytes(name: str, data: bytes) -> List[str]:
    text = data.decode("utf-8-sig", errors="replace")
    stripped = text.strip()
    if name.lower().endswith(".json") and stripped.startswith("["):
        try:
            arr = json.loads(stripped)
            if isinstance(arr, list):
                return [json.dumps(x) if not isinstance(x, str) else x for x in arr]
        except json.JSONDecodeError:
            pass
    return split_text_into_records(text)


# --------------------------- Session ----------------------

if "page" not in st.session_state:
    st.session_state.page = "Dashboard"
if "events" not in st.session_state:
    st.session_state.events = []
if "last_batch" not in st.session_state:
    st.session_state.last_batch = []
if "last_input_name" not in st.session_state:
    st.session_state.last_input_name = ""

# --------------------------- Design system / UI ---------------------------
# A single, consistent design language: one spacing scale, one radius scale,
# one shadow system, and a restrained palette (ink / slate neutrals + a
# single accent color) reused everywhere for visual symmetry.

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

    :root {
        /* ---- Brand & semantic colors (single source of truth) ---- */
        --accent: #f97316;
        --accent-dark: #ea580c;
        --accent-soft: #fff3e8;
        --accent-ring: rgba(249, 115, 22, .18);

        --ink-900: #0b1220;
        --ink-800: #1e293b;
        --ink-700: #334155;
        --ink-600: #475569;
        --ink-500: #64748b;
        --ink-400: #94a3b8;

        --line: #dfe3ea;
        --line-soft: #ebeef3;
        --surface: #ffffff;
        --surface-2: #f8fafc;
        --canvas: #f1f3f7;

        --success: #15803d;
        --success-soft: #ecfdf3;
        --warning: #b45309;
        --warning-soft: #fffaeb;
        --danger: #b91c1c;
        --danger-soft: #fef2f2;
        --info: #1d4ed8;
        --info-soft: #eff6ff;

        /* ---- Consistent scale tokens ---- */
        --radius-sm: 8px;
        --radius-md: 12px;
        --radius-lg: 16px;
        --radius-xl: 20px;

        --shadow-sm: 0 1px 3px rgba(15, 23, 42, .06);
        --shadow-md: 0 10px 24px rgba(15, 23, 42, .08);
        --shadow-lg: 0 20px 48px rgba(15, 23, 42, .12);

        --space-1: 6px;
        --space-2: 10px;
        --space-3: 16px;
        --space-4: 24px;
        --space-5: 30px;
    }

    html, body, [class*="css"], .stApp, .stApp * {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif !important;
    }

    .stApp {
        background: var(--canvas);
        font-size: 16px;
    }

    #MainMenu, footer { visibility: hidden; }

    [data-testid="stHeader"] {
        background: rgba(241,243,247,0.92);
    }

    .block-container {
        padding-top: 1.7rem;
        max-width: 1260px;
    }

    /* ===============================================================
       TEXT-COLOR SAFETY NET
       Streamlit injects its own CSS-in-JS classes on native text
       elements (p, span, label, div, headings) which can carry higher
       or equal specificity than plain classes and can end up matching
       a theme color close to the background — the "hidden text" bug.
       :where() gives this rule ZERO specificity so it always loses to
       any real component class below (.metric-value, .status-pill,
       button text, etc.) while !important still lets it beat
       Streamlit's own un-important theme rules. This is the fix.
       =============================================================== */

    :where(.stApp) :where(p, span, label, li, small, div, h1, h2, h3, h4, h5, h6, a) {
        color: var(--ink-800) !important;
    }

    :where(.stApp) :where(h1, h2, h3, h4, h5, h6) {
        color: var(--ink-900) !important;
        font-weight: 800 !important;
    }

    :where([data-testid="stSidebar"]) :where(p, span, label, li, small, div, h1, h2, h3, h4, h5, h6, a) {
        color: #eef1f6 !important;
    }

    :where([data-testid="stSidebar"]) :where(.stCaption, small) {
        color: #9aa5ba !important;
    }

    section.main .stCaption, section.main small {
        color: var(--ink-500) !important;
    }

    /* Text inputs, textareas, selects — explicit dark text on white */
    section.main .stTextInput input,
    section.main .stTextArea textarea,
    section.main .stNumberInput input,
    section.main div[data-baseweb="select"] * {
        color: var(--ink-900) !important;
    }

    section.main .stTextInput input::placeholder,
    section.main .stTextArea textarea::placeholder {
        color: var(--ink-400) !important;
        opacity: 1;
    }

    /* Code blocks — force a readable, high-contrast style regardless
       of the active theme (fixes dark-text-on-dark-bg / invisible text) */
    section.main .stCodeBlock, section.main pre {
        background: var(--ink-900) !important;
        border-radius: var(--radius-sm) !important;
        border: 1px solid #1e2a3f !important;
    }

    section.main .stCodeBlock code, section.main pre code {
        color: #e7ecf5 !important;
        font-size: 13.5px !important;
    }

    /* Radio / checkbox option text in the main canvas */
    section.main .stRadio label p,
    section.main .stCheckbox label p {
        color: var(--ink-800) !important;
        font-size: 15px !important;
    }

    /* Expander header text */
    section.main .streamlit-expanderHeader,
    section.main .streamlit-expanderHeader p {
        color: var(--ink-900) !important;
        font-weight: 700 !important;
        font-size: 14px !important;
    }

    section.main details summary {
        background: var(--surface);
    }

    /* File uploader */
    section.main [data-testid="stFileUploaderDropzone"] {
        background: var(--surface-2) !important;
        border: 1.5px dashed var(--line) !important;
    }

    section.main [data-testid="stFileUploaderDropzone"] * {
        color: var(--ink-700) !important;
    }

    /* Alerts (success / warning / error boxes) */
    section.main div[data-testid="stAlert"] p {
        font-size: 14.5px !important;
        font-weight: 550;
    }

    /* ================= Sidebar ================= */

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, var(--ink-900) 0%, #0e1626 100%);
        border-right: 1px solid #1e2a3f;
    }

    [data-testid="stSidebar"] hr {
        border-color: #24304a;
        margin: var(--space-3) 0;
    }

    [data-testid="stSidebar"] [data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-size: 22px !important;
    }

    [data-testid="stSidebar"] [data-testid="stMetricLabel"] {
        color: #9aa5ba !important;
        font-size: 12px !important;
        text-transform: uppercase;
        letter-spacing: .5px;
    }

    [data-testid="stSidebar"] .stRadio > label {
        display: none;
    }

    [data-testid="stSidebar"] .stRadio [role="radiogroup"] {
        gap: 3px;
    }

    [data-testid="stSidebar"] .stRadio [role="radiogroup"] label {
        background: transparent;
        border-radius: var(--radius-sm);
        padding: 8px 9px;
        transition: background .15s ease;
        width: 100%;
        border: 1px solid transparent;
    }

    [data-testid="stSidebar"] .stRadio [role="radiogroup"] label p {
        font-size: 14.5px !important;
        font-weight: 550;
    }

    [data-testid="stSidebar"] .stRadio [role="radiogroup"] label:hover {
        background: rgba(255,255,255,.07);
        border-color: rgba(255,255,255,.08);
    }

    [data-testid="stSidebar"] div[data-testid="stButton"] > button {
        background: rgba(255,255,255,.06);
        border: 1px solid rgba(255,255,255,.16);
    }

    [data-testid="stSidebar"] div[data-testid="stButton"] > button p {
        color: #f4f6fa !important;
        font-weight: 650;
    }

    [data-testid="stSidebar"] div[data-testid="stButton"] > button:hover {
        background: rgba(255,255,255,.13);
        border-color: rgba(255,255,255,.28);
    }

    .brand {
        display: flex;
        align-items: center;
        gap: var(--space-3);
        padding: var(--space-1) 0 var(--space-4);
    }

    .brand-icon {
        width: 44px;
        height: 44px;
        border-radius: var(--radius-md);
        display: flex;
        align-items: center;
        justify-content: center;
        background: linear-gradient(135deg, var(--accent) 0%, var(--accent-dark) 100%);
        color: white !important;
        font-size: 21px;
        font-weight: 800;
        box-shadow: 0 10px 22px rgba(249,115,22,.4);
        flex-shrink: 0;
    }

    .brand-title {
        font-size: 20px;
        line-height: 1.15;
        font-weight: 800 !important;
        letter-spacing: -.3px;
        color: #ffffff !important;
    }

    .brand-sub {
        font-size: 12px;
        color: #9aa5ba !important;
        margin-top: 3px;
    }

    .nav-label {
        font-size: 12px;
        font-weight: 800 !important;
        letter-spacing: .6px;
        text-transform: uppercase;
        color: #9aa5ba !important;
        margin: 0 0 var(--space-2) 2px;
    }

    .pipeline-chip {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: 12px;
        color: #9aa5ba !important;
        flex-wrap: wrap;
        line-height: 1.8;
    }

    /* ================= Hero ================= */

    .hero {
        position: relative;
        background: linear-gradient(135deg, var(--ink-900) 0%, #182236 100%);
        border: 1px solid #1e2a3f;
        border-radius: var(--radius-xl);
        padding: var(--space-5) 34px;
        margin-bottom: var(--space-4);
        box-shadow: var(--shadow-lg);
        overflow: hidden;
    }

    .hero::after {
        content: "";
        position: absolute;
        top: -60px;
        right: -60px;
        width: 220px;
        height: 220px;
        background: radial-gradient(circle, rgba(249,115,22,.22) 0%, rgba(249,115,22,0) 70%);
        pointer-events: none;
    }

    .hero-kicker {
        color: #fb923c !important;
        font-size: 12.5px;
        font-weight: 800 !important;
        letter-spacing: 1.5px;
        text-transform: uppercase;
        margin-bottom: var(--space-1);
    }

    .hero h1 {
        color: #ffffff !important;
        font-size: 33px;
        margin: 0;
        letter-spacing: -.7px;
        font-weight: 800 !important;
    }

    .hero p {
        color: #becbe0 !important;
        margin: 10px 0 0;
        font-size: 15px;
        max-width: 680px;
        line-height: 1.65;
    }

    .flow {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: var(--space-2);
        margin-top: var(--space-4);
        position: relative;
    }

    .flow-item {
        background: rgba(255,255,255,.06);
        border: 1px solid rgba(255,255,255,.10);
        border-radius: var(--radius-md);
        padding: 14px 15px;
        transition: background .15s ease, transform .15s ease;
    }

    .flow-item:hover {
        background: rgba(255,255,255,.09);
        transform: translateY(-2px);
    }

    .flow-num {
        color: #fb923c !important;
        font-size: 11px;
        font-weight: 800 !important;
        letter-spacing: .5px;
    }

    .flow-label {
        color: #f4f6fa !important;
        font-size: 14px;
        margin-top: 5px;
        font-weight: 650 !important;
    }

    /* ================= Section headers ================= */

    .section-eyebrow {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 12px;
        font-weight: 800 !important;
        letter-spacing: .6px;
        text-transform: uppercase;
        color: var(--accent-dark) !important;
        background: var(--accent-soft);
        padding: 5px 12px;
        border-radius: 999px;
        margin-bottom: var(--space-2);
    }

    .section-title {
        font-size: 25px;
        font-weight: 800 !important;
        color: var(--ink-900) !important;
        letter-spacing: -.5px;
        margin: 0 0 6px;
    }

    .section-sub {
        color: var(--ink-500) !important;
        font-size: 15px;
        margin-bottom: var(--space-4);
        line-height: 1.6;
    }

    /* ================= Cards (single system, reused everywhere) ================= */

    .metric-card, .panel, .step-card {
        background: var(--surface);
        border: 1px solid var(--line);
        border-radius: var(--radius-lg);
        box-shadow: var(--shadow-sm);
    }

    .metric-card {
        padding: 19px var(--space-3);
        min-height: 100px;
        display: flex;
        flex-direction: column;
        justify-content: center;
        gap: 8px;
        transition: box-shadow .15s ease, transform .15s ease, border-color .15s ease;
    }

    .metric-card:hover {
        box-shadow: var(--shadow-md);
        transform: translateY(-2px);
        border-color: #d7dce4;
    }

    .metric-label {
        color: var(--ink-500) !important;
        font-size: 12.5px !important;
        font-weight: 700 !important;
        text-transform: uppercase;
        letter-spacing: .5px;
        display: flex;
        align-items: center;
        gap: 6px;
    }

    .metric-value {
        color: var(--ink-900) !important;
        font-size: 29px !important;
        font-weight: 800 !important;
        letter-spacing: -.5px;
        line-height: 1;
    }

    .metric-value .unit {
        font-size: 14px !important;
        color: var(--ink-500) !important;
        font-weight: 600 !important;
        margin-left: 4px;
    }

    .metric-value.accent-success { color: var(--success) !important; }
    .metric-value.accent-warning { color: var(--warning) !important; }
    .metric-value.accent-danger  { color: var(--danger) !important; }
    .metric-value.accent-brand   { color: var(--accent-dark) !important; }

    .panel {
        padding: 19px var(--space-3);
        height: 100%;
        display: flex;
        flex-direction: column;
        gap: 5px;
        transition: box-shadow .15s ease, transform .15s ease, border-color .15s ease;
    }

    .panel:hover {
        box-shadow: var(--shadow-md);
        transform: translateY(-2px);
        border-color: #d7dce4;
    }

    .panel-icon {
        font-size: 22px;
        margin-bottom: 3px;
    }

    .panel b {
        color: var(--ink-900) !important;
        font-size: 15px !important;
    }

    .panel small {
        color: var(--ink-500) !important;
        font-size: 13px !important;
        line-height: 1.6;
    }

    /* ================= Status pills ================= */

    .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 5px 12px;
        border-radius: 999px;
        font-size: 12px !important;
        font-weight: 800 !important;
        letter-spacing: .2px;
        border: 1px solid transparent;
    }

    .status-success { background: var(--success-soft); color: var(--success) !important; }
    .status-warning { background: var(--warning-soft); color: var(--warning) !important; }
    .status-danger  { background: var(--danger-soft);  color: var(--danger) !important; }
    .status-info    { background: var(--info-soft);    color: var(--info) !important; }

    /* ================= Empty states ================= */

    .empty-state {
        text-align: center;
        background: var(--surface);
        border: 1.5px dashed var(--line);
        border-radius: var(--radius-lg);
        padding: 50px 28px;
        margin: var(--space-2) 0 var(--space-4);
    }

    .empty-icon {
        font-size: 36px;
        margin-bottom: var(--space-2);
        opacity: .85;
    }

    .empty-title {
        font-size: 18.5px !important;
        font-weight: 800 !important;
        color: var(--ink-900) !important;
    }

    .empty-text {
        color: var(--ink-500) !important;
        font-size: 14px !important;
        margin-top: 6px;
    }

    /* ================= Step cards (pipeline view) ================= */

    .step-card {
        padding: 18px var(--space-4);
        margin-bottom: var(--space-2);
        transition: box-shadow .15s ease, border-color .15s ease;
    }

    .step-card:hover {
        border-color: #d7dce4;
        box-shadow: var(--shadow-md);
    }

    .step-row {
        display: flex;
        gap: var(--space-3);
        align-items: flex-start;
    }

    .step-number {
        min-width: 38px;
        height: 38px;
        border-radius: var(--radius-sm);
        background: var(--accent-soft);
        color: var(--accent-dark) !important;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 13px !important;
        font-weight: 900 !important;
        flex-shrink: 0;
    }

    .step-title {
        color: var(--ink-900) !important;
        font-weight: 800 !important;
        font-size: 15px !important;
    }

    .step-desc {
        color: var(--ink-500) !important;
        font-size: 13.5px !important;
        margin-top: 4px;
        line-height: 1.65;
    }

    /* ================= Inputs & controls (unified) ================= */

    section.main .stTextInput input,
    section.main .stTextArea textarea,
    section.main .stFileUploader section {
        border-radius: var(--radius-sm) !important;
        border: 1px solid #cdd3dd !important;
        background: var(--surface) !important;
        font-size: 15px !important;
    }

    section.main .stTextInput input:focus,
    section.main .stTextArea textarea:focus {
        border-color: var(--accent) !important;
        box-shadow: 0 0 0 3px var(--accent-ring) !important;
    }

    div[data-testid="stButton"] > button {
        border-radius: var(--radius-sm);
        font-weight: 700;
        font-size: 14.5px !important;
        min-height: 46px;
        border: 1px solid var(--line);
        transition: all .15s ease;
    }

    div[data-testid="stButton"] > button[kind="primary"] {
        background: linear-gradient(135deg, var(--accent) 0%, var(--accent-dark) 100%) !important;
        border-color: var(--accent-dark) !important;
        box-shadow: 0 10px 22px var(--accent-ring);
    }

    div[data-testid="stButton"] > button[kind="primary"] p {
        color: #ffffff !important;
        font-weight: 750 !important;
    }

    div[data-testid="stButton"] > button[kind="primary"]:hover {
        box-shadow: 0 12px 26px rgba(249,115,22,.32);
        transform: translateY(-1px);
    }

    div[data-testid="stButton"] > button[kind="secondary"] {
        background: var(--surface);
    }

    div[data-testid="stButton"] > button[kind="secondary"] p {
        color: var(--ink-800) !important;
        font-weight: 650 !important;
    }

    div[data-testid="stButton"] > button[kind="secondary"]:hover {
        border-color: var(--accent);
    }

    div[data-testid="stDownloadButton"] > button {
        border-radius: var(--radius-sm);
        min-height: 44px;
        font-weight: 700;
        font-size: 14px !important;
        border: 1px solid var(--line);
        background: var(--surface);
        transition: all .15s ease;
    }

    div[data-testid="stDownloadButton"] > button p {
        color: var(--ink-800) !important;
        font-weight: 650 !important;
    }

    div[data-testid="stDownloadButton"] > button:hover {
        border-color: var(--accent);
        transform: translateY(-1px);
    }

    div[data-testid="stDownloadButton"] > button:hover p {
        color: var(--accent-dark) !important;
    }

    .stRadio [role="radiogroup"] {
        gap: 4px;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid var(--line);
        border-radius: var(--radius-md);
        overflow: hidden;
        box-shadow: var(--shadow-sm);
        font-size: 14px !important;
    }

    .streamlit-expanderHeader {
        border-radius: var(--radius-sm) !important;
        font-weight: 700 !important;
        font-size: 14px !important;
    }

    /* ================= Footer ================= */

    .footer {
        color: var(--ink-400) !important;
        text-align: center;
        font-size: 12.5px !important;
        padding: 24px 0 8px;
        border-top: 1px solid var(--line-soft);
        margin-top: var(--space-5);
    }

    /* ================= Responsive symmetry ================= */

    @media (max-width: 900px) {
        .flow { grid-template-columns: repeat(2, 1fr); }
        .hero h1 { font-size: 25px; }
    }
</style>
""", unsafe_allow_html=True)


def status_pill_html(status: str) -> str:
    mapping = {
        "SUCCESS": ("status-success", "✅"),
        "PARTIAL": ("status-warning", "🟠"),
        "FAILED": ("status-danger", "🔴"),
    }
    css_class, icon = mapping.get(status, ("status-info", "•"))
    return f'<span class="status-pill {css_class}">{icon} {status}</span>'


def metric_card(label: str, value: str, icon: str = "", accent: str = "") -> str:
    accent_class = f"accent-{accent}" if accent else ""
    return (
        f'<div class="metric-card">'
        f'<div class="metric-label">{icon} {label}</div>'
        f'<div class="metric-value {accent_class}">{value}</div>'
        f'</div>'
    )


def render_metric_row(items: List[Tuple[str, str, str, str]]) -> None:
    """items: list of (label, value, icon, accent)."""
    cols = st.columns(len(items))
    for col, (label, value, icon, accent) in zip(cols, items):
        with col:
            st.markdown(metric_card(label, value, icon, accent), unsafe_allow_html=True)


# --------------------------- Sidebar ---------------------------

with st.sidebar:
    st.markdown("""
    <div class="brand">
        <div class="brand-icon">⚡</div>
        <div>
            <div class="brand-title">ULPF</div>
            <div class="brand-sub">Universal Log Pre-processing Framework</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.caption(f"Production workspace  •  v{APP_VERSION}")
    st.divider()

    st.markdown('<div class="nav-label">🧭 Workspace</div>', unsafe_allow_html=True)
    pages = [
        "📊 Dashboard",
        "⚙️ Ingest & Process",
        "🔎 Event Explorer",
        "🧬 Schema & Pipeline",
        "🧪 Validation Lab",
    ]
    display_page = st.radio(
        "Navigation",
        pages,
        key="page_nav",
        label_visibility="collapsed",
    )

    page_map = {
        "📊 Dashboard": "Dashboard",
        "⚙️ Ingest & Process": "Ingest & Process",
        "🔎 Event Explorer": "Event Explorer",
        "🧬 Schema & Pipeline": "Schema & Pipeline",
        "🧪 Validation Lab": "Validation Lab",
    }
    st.session_state.page = page_map[display_page]

    st.divider()
    st.markdown('<div class="nav-label">📦 Session</div>', unsafe_allow_html=True)
    sc1, sc2 = st.columns(2)
    with sc1:
        st.metric("Events", len(st.session_state.events))
    with sc2:
        st.metric("Batch", len(st.session_state.last_batch))

    if st.button("🗑️  Clear session", use_container_width=True):
        st.session_state.events = []
        st.session_state.last_batch = []
        st.session_state.last_input_name = ""
        st.rerun()

    st.divider()
    st.markdown('<div class="nav-label">Pipeline</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="pipeline-chip">📥 Ingest&nbsp;→&nbsp;🧠 Parse&nbsp;→&nbsp;🧩 Normalize&nbsp;→&nbsp;📤 Export</div>',
        unsafe_allow_html=True,
    )

# --------------------------- Header ---------------------------

st.markdown("""
<div class="hero">
    <div class="hero-kicker">Universal Log Processing</div>
    <h1>⚡ ULPF Control Center</h1>
    <p>Transform heterogeneous logs into consistent, traceable Universal Events — without losing the original record.</p>
    <div class="flow">
        <div class="flow-item"><div class="flow-num">STEP 01</div><div class="flow-label">📥 Ingest</div></div>
        <div class="flow-item"><div class="flow-num">STEP 02</div><div class="flow-label">🧠 Parse</div></div>
        <div class="flow-item"><div class="flow-num">STEP 03</div><div class="flow-label">🧩 Normalize</div></div>
        <div class="flow-item"><div class="flow-num">STEP 04</div><div class="flow-label">📤 Export</div></div>
    </div>
</div>
""", unsafe_allow_html=True)

# =========================== DASHBOARD ========================

if st.session_state.page == "Dashboard":
    events = st.session_state.events
    total = len(events)

    st.markdown('<div class="section-eyebrow">Overview</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">📊 Dashboard</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Operational overview of the current processing session.</div>', unsafe_allow_html=True)

    if total == 0:
        st.markdown("""
        <div class="empty-state">
            <div class="empty-icon">📭</div>
            <div class="empty-title">No events processed yet</div>
            <div class="empty-text">Start from Ingest &amp; Process to transform your first log stream.</div>
        </div>
        """, unsafe_allow_html=True)

        panels = [
            ("📥", "Flexible ingest", "Paste or upload common log files."),
            ("🧠", "Smart parsing", "AI parser with local fallback."),
            ("🧬", "Universal schema", "Normalize fields consistently."),
            ("📤", "Export ready", "JSON, JSONL and CSV output."),
        ]
        cols = st.columns(4)
        for col, (icon, title, desc) in zip(cols, panels):
            with col:
                st.markdown(
                    f'<div class="panel"><div class="panel-icon">{icon}</div>'
                    f'<b>{title}</b><small>{desc}</small></div>',
                    unsafe_allow_html=True,
                )
    else:
        success = sum(1 for e in events if e.processing_status == "SUCCESS")
        partial = sum(1 for e in events if e.processing_status == "PARTIAL")
        failed = sum(1 for e in events if e.processing_status == "FAILED")
        avg_conf = sum(e.confidence for e in events) / total if total else 0

        render_metric_row([
            ("Total events", f"{total:,}", "📦", ""),
            ("Success", f"{success:,}", "✅", "success"),
            ("Partial", f"{partial:,}", "🟠", "warning"),
            ("Failed", f"{failed:,}", "🔴", "danger"),
            ("Avg confidence", f"{avg_conf:.0%}", "🎯", "brand"),
        ])

        st.markdown('<div style="height:22px"></div>', unsafe_allow_html=True)
        st.markdown('<div class="section-eyebrow">Latest activity</div>', unsafe_allow_html=True)
        st.markdown('<div class="section-title" style="font-size:17px;">🕘 Recent events</div>', unsafe_allow_html=True)

        rows = []
        for e in events[-20:]:
            rows.append({
                "Seq": e.event_sequence,
                "Category": e.event_category,
                "Type": e.event_type,
                "Severity": e.severity,
                "User": e.user_name or "",
                "Host": e.host_name or "",
                "Source IP": e.source_ip or "",
                "Status": e.processing_status,
                "Confidence": f"{e.confidence:.0%}",
            })
        st.dataframe(rows, use_container_width=True, hide_index=True)

# ======================= INGEST & PROCESS =====================

elif st.session_state.page == "Ingest & Process":
    st.markdown('<div class="section-eyebrow">Pipeline stage 1–3</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">⚙️ Ingest &amp; Process</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Bring in raw logs, preview the records, then normalize them into Universal Events.</div>', unsafe_allow_html=True)

    st.markdown("##### 📥 Choose an input source")
    input_mode = st.radio(
        "Input source",
        ["✍️ Paste / type logs", "📁 Upload file"],
        horizontal=True,
        label_visibility="collapsed",
    )

    records: List[str] = []
    input_name = ""

    if input_mode == "✍️ Paste / type logs":
        text = st.text_area(
            "Raw log stream",
            height=250,
            placeholder='Paste ANY log format here...\n\nExamples:\nSep  9 14:32:29 firewall-01 sshd[4821]: Failed password for root from 198.51.100.77\n{"user":"john","action":"login","status":"success"}\n2026-09-08T23:05:44Z [WORKER-7] WARN Data corrupted',
            label_visibility="collapsed",
        )
        if text.strip():
            records = split_text_into_records(text)
            input_name = "pasted_logs"
    else:
        uploaded = st.file_uploader(
            "Choose a log file",
            type=["txt", "log", "json", "jsonl", "csv"],
            help="Supported formats: TXT, LOG, JSON, JSONL and CSV.",
            label_visibility="collapsed",
        )
        if uploaded:
            records = parse_uploaded_bytes(uploaded.name, uploaded.getvalue())
            input_name = uploaded.name
            st.success(f"Loaded **{len(records):,}** records from `{uploaded.name}`")

    if records:
        st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)
        st.markdown(
            metric_card("Ready to process", f'{len(records):,} <span class="unit">records</span>', "📋", ""),
            unsafe_allow_html=True,
        )
        st.markdown('<div style="height:10px"></div>', unsafe_allow_html=True)
        with st.expander("👁️ Preview first records"):
            for i, r in enumerate(records[:5], 1):
                st.code(f"[{i}] {r[:200]}", language="text")

    st.markdown('<div style="height:8px"></div>', unsafe_allow_html=True)
    st.markdown("##### 🎛️ Processing controls")
    b1, b2 = st.columns([1, 1])
    with b1:
        process_clicked = st.button(
            "⚡ Process records",
            type="primary",
            use_container_width=True,
            disabled=not records,
        )
    with b2:
        append_mode = st.checkbox("Append to existing session", value=True)

    if process_clicked:
        engine = ULPF(api_key=_get_key())
        progress = st.progress(0)
        status = st.empty()

        def _on_progress(done, total):
            progress.progress(done / total)
            status.caption(f"Processing… {done:,} / {total:,} unique records")

        t0 = time.perf_counter()
        batch = engine.process_batch(records, on_progress=_on_progress)
        elapsed = time.perf_counter() - t0

        progress.progress(1.0)
        status.empty()

        if append_mode:
            st.session_state.events.extend(batch)
        else:
            st.session_state.events = batch

        st.session_state.last_batch = batch
        st.session_state.last_input_name = input_name
        st.success(f"Processed **{len(batch):,}** records in **{elapsed:.2f}s**.")
        st.rerun()

    if st.session_state.last_batch:
        batch = st.session_state.last_batch
        st.markdown('<div style="height:8px"></div>', unsafe_allow_html=True)
        st.markdown('<div class="section-eyebrow">Result</div>', unsafe_allow_html=True)
        st.markdown('<div class="section-title" style="font-size:17px;">📦 Last batch</div>', unsafe_allow_html=True)

        render_metric_row([
            ("Records", f"{len(batch):,}", "📦", ""),
            ("Success", f"{sum(1 for e in batch if e.processing_status == 'SUCCESS'):,}", "✅", "success"),
            ("Partial", f"{sum(1 for e in batch if e.processing_status == 'PARTIAL'):,}", "🟠", "warning"),
            ("Failed", f"{sum(1 for e in batch if e.processing_status == 'FAILED'):,}", "🔴", "danger"),
        ])

        st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)
        rows = []
        for e in batch:
            rows.append({
                "Seq": e.event_sequence,
                "Category": e.event_category,
                "Type": e.event_type,
                "Severity": e.severity,
                "User": e.user_name or "",
                "Host": e.host_name or "",
                "Source IP": e.source_ip or "",
                "Status": e.processing_status,
                "Confidence": f"{e.confidence:.0%}",
            })
        st.dataframe(rows, use_container_width=True, hide_index=True)

        st.markdown('<div style="height:8px"></div>', unsafe_allow_html=True)
        st.markdown("##### 📤 Export last batch")
        e1, e2, e3 = st.columns(3)
        engine = ULPF()
        with e1:
            st.download_button("🧾 JSON", engine.export_json(batch), "ulpf_events.json", "application/json", use_container_width=True)
        with e2:
            st.download_button("📄 JSONL", engine.export_jsonl(batch), "ulpf_events.jsonl", use_container_width=True)
        with e3:
            st.download_button("📊 CSV", engine.export_csv(batch), "ulpf_events.csv", "text/csv", use_container_width=True)

# ========================= EVENT EXPLORER =====================

elif st.session_state.page == "Event Explorer":
    st.markdown('<div class="section-eyebrow">Inspect &amp; trace</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">🔎 Event Explorer</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Search, inspect and trace normalized events back to their preserved raw records.</div>', unsafe_allow_html=True)

    if not st.session_state.events:
        st.markdown("""
        <div class="empty-state">
            <div class="empty-icon">🔍</div>
            <div class="empty-title">No events available</div>
            <div class="empty-text">Process some logs first, then return here to explore them.</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        events = st.session_state.events
        search = st.text_input("🔎 Search events", placeholder="Search in raw event...")

        filtered = events
        if search:
            q = search.lower()
            filtered = [e for e in filtered if q in e.raw_event.lower()]

        st.markdown('<div style="height:6px"></div>', unsafe_allow_html=True)
        st.markdown(
            metric_card("Matching events", f"{len(filtered):,}", "🎯", ""),
            unsafe_allow_html=True,
        )
        st.markdown('<div style="height:14px"></div>', unsafe_allow_html=True)

        if filtered:
            rows = []
            for e in filtered[:50]:
                rows.append({
                    "Seq": e.event_sequence,
                    "Category": e.event_category,
                    "Type": e.event_type,
                    "Severity": e.severity,
                    "User": e.user_name or "",
                    "Host": e.host_name or "",
                    "Source IP": e.source_ip or "",
                    "Status": e.processing_status,
                    "Confidence": f"{e.confidence:.0%}",
                })
            st.dataframe(rows, use_container_width=True, hide_index=True)

            options = {
                f"#{e.event_sequence}  •  {e.event_type}  •  {e.severity}": e
                for e in filtered[:20]
            }
            st.markdown('<div style="height:6px"></div>', unsafe_allow_html=True)
            selected = st.selectbox("📌 Open event", list(options.keys()))
            e = options[selected]

            st.markdown(status_pill_html(e.processing_status), unsafe_allow_html=True)
            st.markdown('<div style="height:8px"></div>', unsafe_allow_html=True)

            with st.expander("🧬 Normalized event", expanded=True):
                st.json(e.to_dict())

            with st.expander("🛡️ Raw event — preserved", expanded=True):
                st.code(e.raw_event)
        else:
            st.warning("No events match that search.")

# ======================= SCHEMA & PIPELINE ====================

elif st.session_state.page == "Schema & Pipeline":
    st.markdown('<div class="section-eyebrow">Architecture</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">🧬 Schema &amp; Pipeline</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">A visual view of how ULPF converts an arbitrary log line into a Universal Event.</div>', unsafe_allow_html=True)

    steps = [
        ("01", "📥 Raw ingestion", "Accept any log format and split the input into individual records."),
        ("02", "🧠 Parsing", "Extract structured fields from each unique record in parallel."),
        ("03", "🛟 Fallback parsing", "Use local pattern-based parsing when the primary parser cannot fully resolve a record."),
        ("04", "🧩 Normalization", "Map extracted attributes onto the Universal Event Schema."),
        ("05", "🎯 Confidence scoring", "Use confidence to determine SUCCESS, PARTIAL or FAILED processing status."),
        ("06", "📤 Export", "Export normalized events as JSON, JSONL or CSV while preserving the raw event."),
    ]

    for num, title, desc in steps:
        st.markdown(
            f'<div class="step-card"><div class="step-row">'
            f'<div class="step-number">{num}</div>'
            f'<div><div class="step-title">{title}</div>'
            f'<div class="step-desc">{desc}</div></div></div></div>',
            unsafe_allow_html=True,
        )

    st.markdown('<div style="height:10px"></div>', unsafe_allow_html=True)
    st.markdown("##### 🔐 Core guarantees")
    guarantees = [
        ("🛡️", "Raw preservation", "The original event is retained for traceability."),
        ("🔗", "Traceability", "Normalized events retain identifiers and provenance metadata."),
        ("🔄", "Fallback resilience", "Local parsing keeps processing moving when smart parsing fails."),
    ]
    cols = st.columns(3)
    for col, (icon, title, desc) in zip(cols, guarantees):
        with col:
            st.markdown(
                f'<div class="panel"><div class="panel-icon">{icon}</div>'
                f'<b>{title}</b><small>{desc}</small></div>',
                unsafe_allow_html=True,
            )

# ========================= VALIDATION LAB =====================

elif st.session_state.page == "Validation Lab":
    st.markdown('<div class="section-eyebrow">Fixtures &amp; QA</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-title">🧪 Validation Lab</div>', unsafe_allow_html=True)
    st.markdown('<div class="section-sub">Run the built-in fixtures across different log formats and inspect the resulting normalization.</div>', unsafe_allow_html=True)

    test_logs = [
        "user=test action=login outcome=success",
        '{"user":{"name":"john"},"source":{"ip":"1.2.3.4"},"event":{"action":"login","outcome":"success"}}',
        'Sep  9 14:32:29 firewall-01 sshd[4821]: Failed password for root from 198.51.100.77 port 43821 ssh2',
        'CEF:0|Vendor|Product|1.0|event|type|5|src=1.2.3.4 dst=5.6.7.8 spt=111 dpt=222 proto=tcp user=admin act=allow',
        '2026-09-08T23:05:44.112Z [WORKER-7] WARN Data corrupted in payload. audit_log_id=9928 status=PARTIAL_SUCCESS',
    ]

    run_clicked = st.button("▶️ Run test suite", type="primary", use_container_width=False)

    if run_clicked:
        engine = ULPF(api_key=_get_key())
        results = engine.process_batch(test_logs)

        success = sum(1 for e in results if e.processing_status in {"SUCCESS", "PARTIAL"})
        st.success(f"{success}/{len(results)} events processed successfully")

        rows = []
        for e in results:
            rows.append({
                "Category": e.event_category,
                "Type": e.event_type,
                "Severity": e.severity,
                "User": e.user_name or "",
                "Host": e.host_name or "",
                "Status": e.processing_status,
                "Confidence": f"{e.confidence:.0%}",
            })
        st.dataframe(rows, use_container_width=True, hide_index=True)

        for e in results:
            if e.warnings:
                with st.expander(f"⚠️ Warnings for #{e.event_sequence}"):
                    for w in e.warnings:
                        st.write(f"- {w}")

    st.markdown('<div style="height:10px"></div>', unsafe_allow_html=True)
    st.markdown("##### 🧾 Test fixtures")
    for i, log in enumerate(test_logs, 1):
        with st.expander(f"Fixture {i}  •  {log[:70]}"):
            st.code(log)

# --------------------------- Footer ----------------------------

st.markdown(
    f'<div class="footer">ULPF {APP_VERSION}  •  Universal Event Schema {SCHEMA_VERSION}  •  Ingest → Parse → Normalize → Export</div>',
    unsafe_allow_html=True,
)