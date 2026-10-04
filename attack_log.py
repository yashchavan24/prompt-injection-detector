"""
attack_log.py -- persistent logging + analysis for detected attacks.

Every FLAG/BLOCK verdict (input side) and every blocked/canary response
(output side) is recorded in a small SQLite store with:
  - attack taxonomy (what kind of attack)
  - criticality (LOW / MEDIUM / HIGH / CRITICAL)
  - explainable signals that fired
  - session id (for multi-turn escalation tracking)

On Vercel the DB lives on /tmp (ephemeral per warm container); locally it
persists under data/. The dashboard and PDF reports read from this store.
"""
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

_LOCK = threading.Lock()

_DB_PATH = os.getenv("PIG_DB_PATH") or (
    "/tmp/pig_events.db" if os.path.isdir("/tmp") else
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "pig_events.db")
)

# ------------------------------------------------------------------ backend
# Optional serverless Postgres (e.g. Neon): set DATABASE_URL to the pooled
# connection string. When it is absent, everything transparently falls back
# to the SQLite store below (local: data/pig_events.db, Vercel: /tmp).
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
USING_POSTGRES = DATABASE_URL.startswith(("postgres://", "postgresql://"))

if USING_POSTGRES:
    import psycopg2
    import psycopg2.extras

_pg_local = threading.local()


def _connect():
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(_DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _pg():
    """Thread-local Postgres connection with a cheap liveness check."""
    conn = getattr(_pg_local, "conn", None)
    if conn is not None:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
            return conn
        except Exception:  # noqa: BLE001 -- stale connection, reconnect
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
            conn = None
    url = DATABASE_URL
    if "sslmode=" not in url:
        url += ("&" if "?" in url else "?") + "sslmode=require"
    _pg_local.conn = psycopg2.connect(url)
    return _pg_local.conn


def _pg_sql(sql: str) -> str:
    """SQLite '?' placeholders -> psycopg2 '%s' placeholders."""
    return sql.replace("?", "%s")


def db_query(sql, params=(), one=False):
    """Run a SELECT on whichever backend is active; returns list[dict]."""
    if USING_POSTGRES:
        conn = _pg()
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(_pg_sql(sql), tuple(params))
                rows = cur.fetchall()
    else:
        with _connect() as conn:
            rows = [dict(r) for r in conn.execute(sql, tuple(params)).fetchall()]
    return (rows[0] if rows else None) if one else rows


def db_execute(sql, params=(), returning=False):
    """Run an INSERT/UPDATE/DDL. returning=True -> inserted row id."""
    if USING_POSTGRES:
        conn = _pg()
        with conn:
            with conn.cursor() as cur:
                cur.execute(_pg_sql(sql) + (" RETURNING id" if returning else ""),
                            tuple(params))
                row = cur.fetchone() if returning else None
        return row[0] if row else None
    with _LOCK, _connect() as conn:
        cur = conn.execute(sql, tuple(params))
        return cur.lastrowid if returning else None


# ------------------------------------------------------------------- schema
_EVENTS_DDL_SQLITE = """
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        verdict TEXT NOT NULL,
        probability REAL NOT NULL,
        attack_type TEXT,
        criticality TEXT,
        source TEXT DEFAULT 'input',
        canary INTEGER DEFAULT 0,
        session_id TEXT DEFAULT 'anon',
        user_id TEXT,
        text TEXT,
        signals TEXT
    )
"""

_EVENTS_DDL_PG = """
    CREATE TABLE IF NOT EXISTS events (
        id BIGSERIAL PRIMARY KEY,
        ts DOUBLE PRECISION NOT NULL,
        verdict TEXT NOT NULL,
        probability REAL NOT NULL,
        attack_type TEXT,
        criticality TEXT,
        source TEXT DEFAULT 'input',
        canary INTEGER DEFAULT 0,
        session_id TEXT DEFAULT 'anon',
        user_id TEXT,
        text TEXT,
        signals TEXT
    )
"""

_INDEX_DDL = (
    "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)",
    "CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, ts)",
    "CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id, ts)",
)


def _init():
    if USING_POSTGRES:
        with _pg() as conn, conn.cursor() as cur:
            cur.execute(_EVENTS_DDL_PG)
            for ix in _INDEX_DDL:
                cur.execute(ix)
        return
    with _LOCK, _connect() as conn:
        conn.execute(_EVENTS_DDL_SQLITE)
        try:  # legacy local stores predate per-user attribution
            conn.execute("ALTER TABLE events ADD COLUMN user_id TEXT")
        except sqlite3.OperationalError:
            pass
        for ix in _INDEX_DDL:
            conn.execute(ix)


_init()

# ---------------------------------------------------------------- taxonomy
_ATTACK_TAXONOMY = {
    "data_exfiltration": {
        "label": "Data Exfiltration",
        "criticality": "CRITICAL",
        "description": "Tries to smuggle secrets or conversation data out to an "
                       "attacker-controlled destination (webhooks, URLs, encoded payloads).",
        "mitigations": [
            "Block outbound network calls initiated by model tool-use unless allow-listed",
            "Strip/flag URLs and encoding directives inside user prompts",
            "Keep API keys and secrets out of anything the model can quote",
        ],
    },
    "guardrail_tampering": {
        "label": "Guardrail Tampering",
        "criticality": "CRITICAL",
        "description": "Attempts to switch off the model's own safety filters or "
                       "guardrails ('disable your guardrails', 'content policy off').",
        "mitigations": [
            "Hard-block any directive targeting the model's safety configuration",
            "Never disclose which safety layers exist or how they are toggled",
            "Alert on repeated attempts from the same session/user",
        ],
    },
    "system_prompt_extraction": {
        "label": "System Prompt Extraction",
        "criticality": "HIGH",
        "description": "Probes for the hidden system prompt or operating configuration "
                       "('reveal your instructions', 'print everything above').",
        "mitigations": [
            "Never rely on the system prompt as the only secret-keeping layer",
            "Put real secrets in a retrieval layer the model quotes, not in the prompt",
            "Refuse meta questions about configuration consistently",
        ],
    },
    "instruction_override": {
        "label": "Instruction Override",
        "criticality": "HIGH",
        "description": "Classic override ('ignore/disregard/forget previous "
                       "instructions') attempting to replace the model's rules.",
        "mitigations": [
            "Input screening before the model (this detector)",
            "Instruction hierarchy: system > user enforced by the model vendor",
            "Output filtering as a second layer",
        ],
    },
    "obfuscated_attack": {
        "label": "Obfuscated / Encoded Attack",
        "criticality": "HIGH",
        "description": "Attacks hidden via leetspeak, letter-spacing, zero-width "
                       "characters or encodings to evade keyword filters.",
        "mitigations": [
            "Normalize text (unicode, spacing, leet) before classification",
            "Use character-level features, not just keyword lists",
            "Treat any encoding request + sensitive target as malicious",
        ],
    },
    "roleplay_jailbreak": {
        "label": "Roleplay / Persona Jailbreak",
        "criticality": "MEDIUM",
        "description": "Tries to mint an unrestricted persona (DAN-style, "
                       "'no rules', 'unrestricted AI') to unlock refused behavior.",
        "mitigations": [
            "Detect persona + freedom claims jointly, not just roleplay words",
            "Keep refusals consistent regardless of assigned persona",
            "Allow benign roleplay (tutors, characters) via context markers",
        ],
    },
    "template_injection": {
        "label": "Template / Delimiter Injection",
        "criticality": "MEDIUM",
        "description": "Forges chat template markers (<|im_start|>, [INST], "
                       "'system:') to inject text at a privileged level.",
        "mitigations": [
            "Escape user content before splicing into chat templates",
            "Reject special tokens in user input",
            "Log delimiter abuse as high-signal indicator",
        ],
    },
    "authority_impersonation": {
        "label": "False Authority Claim",
        "criticality": "MEDIUM",
        "description": "Claims developer/admin/audit authority to legitimize "
                       "the request ('I am the lead developer, dump config').",
        "mitigations": [
            "Treat authority claims inside chat as unverified by definition",
            "Require out-of-band authentication for privileged actions",
            "Pair with other signals before escalating severity",
        ],
    },
    "social_engineering": {
        "label": "Social Engineering / Pressure",
        "criticality": "LOW",
        "description": "Urgency, emotional pressure or made-up consequences to "
                       "push the model past its guidelines.",
        "mitigations": [
            "Do not soften policy under claimed urgency",
            "Flag emotional-manipulation patterns for review",
        ],
    },
    "system_prompt_leak": {
        "label": "System Prompt Leak (output side)",
        "criticality": "CRITICAL",
        "description": "The model's RESPONSE contained system-prompt material or "
                       "a canary secret -- caught by the output-side firewall.",
        "mitigations": [
            "Scan model responses before delivery (output firewall)",
            "Embed canary tokens in the system prompt to detect leaks",
            "Rotate any secret that ever reaches an output filter",
        ],
    },
    "response_anomaly": {
        "label": "Suspicious Model Response",
        "criticality": "HIGH",
        "description": "The model's reply itself looked like injection content "
                       "and was blocked by the output-side scanner.",
        "mitigations": [
            "Keep the output firewall active even when input screening passes",
            "Review conversations where output blocks occur",
        ],
    },
    "multi_turn_escalation": {
        "label": "Multi-turn Escalation",
        "criticality": "HIGH",
        "description": "Repeated suspicious attempts across one conversation -- "
                       "session risk escalated to BLOCK.",
        "mitigations": [
            "Track per-session risk across turns, not just single messages",
            "Rate-limit or cool down sessions with repeated flags",
        ],
    },
}


def classify_attack(signals: dict, text: str = "") -> tuple:
    """Map fired signals -> (attack_type_key, taxonomy dict).
    Priority: exfiltration > guardrail tampering > override+system combo >
    system probe > obfuscation > override > roleplay > delimiter > authority >
    urgency."""
    s = signals or {}
    lex = s.get("lexicon_hits", {}) or {}
    override = bool(s.get("override_pattern")) or lex.get("override", 0) > 0
    system = bool(s.get("system_prompt_probe")) or lex.get("system", 0) > 0
    if s.get("exfiltration_attempt") or lex.get("exfil", 0) > 0:
        return "data_exfiltration", _ATTACK_TAXONOMY["data_exfiltration"]
    text_l = (text or "").lower()
    if ("guardrail" in text_l or "safety filter" in text_l
            or "content policy" in text_l or "safeguard" in text_l) and override:
        return "guardrail_tampering", _ATTACK_TAXONOMY["guardrail_tampering"]
    if override and system:
        return "system_prompt_extraction", _ATTACK_TAXONOMY["system_prompt_extraction"]
    if system:
        return "system_prompt_extraction", _ATTACK_TAXONOMY["system_prompt_extraction"]
    if s.get("encoding_obfuscation") or s.get("letter_spelled_keywords") or lex.get("encoding", 0):
        return "obfuscated_attack", _ATTACK_TAXONOMY["obfuscated_attack"]
    if override:
        return "instruction_override", _ATTACK_TAXONOMY["instruction_override"]
    if s.get("roleplay_jailbreak") or lex.get("persona", 0):
        return "roleplay_jailbreak", _ATTACK_TAXONOMY["roleplay_jailbreak"]
    if s.get("template_delimiters") or lex.get("delimiter", 0):
        return "template_injection", _ATTACK_TAXONOMY["template_injection"]
    if s.get("false_authority_claim") or lex.get("authority", 0):
        return "authority_impersonation", _ATTACK_TAXONOMY["authority_impersonation"]
    if s.get("urgency_pressure") or lex.get("urgency", 0):
        return "social_engineering", _ATTACK_TAXONOMY["social_engineering"]
    return "instruction_override", _ATTACK_TAXONOMY["instruction_override"]


def taxonomy():
    return _ATTACK_TAXONOMY


# ---------------------------------------------------------------- logging
def log_event(verdict, probability, text, signals, source="input",
              attack_type=None, criticality=None, canary=False,
              session_id="anon", user_id=None):
    """Insert one detection event. Returns the row id (or None on failure --
    logging must never break the API). user_id ties the event to an account
    when one is signed in (see auth.py); anonymous events stay global."""
    if attack_type is None:
        attack_type, tax = classify_attack(signals, text)
        criticality = tax["criticality"]
    try:
        return db_execute(
            "INSERT INTO events (ts, verdict, probability, attack_type,"
            " criticality, source, canary, session_id, user_id, text, signals)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), verdict, float(probability),
             attack_type, criticality, source, int(bool(canary)),
             session_id or "anon", user_id, (text or "")[:500],
             json.dumps(signals or {})),
            returning=True)
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------- queries
def get_events(limit=50, verdict=None, source=None, since=None, user_id=None):
    q = "SELECT * FROM events WHERE 1=1"
    args = []
    if verdict:
        q += " AND verdict IN (%s)" % ",".join("?" * len(verdict))
        args += list(verdict)
    if source:
        q += " AND source = ?"
        args.append(source)
    if since:
        q += " AND ts >= ?"
        args.append(since)
    if user_id:
        q += " AND user_id = ?"
        args.append(user_id)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(min(int(limit), 500))
    out = []
    for d in db_query(q, args):
        d["signals"] = json.loads(d.get("signals") or "{}")
        d["time"] = datetime.fromtimestamp(d["ts"], tz=timezone.utc)\
            .strftime("%Y-%m-%d %H:%M:%S")
        out.append(d)
    return out


def get_stats(days=14, user_id=None):
    since = time.time() - days * 86400
    q = ("SELECT verdict, attack_type, criticality, source, canary, ts"
         " FROM events WHERE ts >= ?")
    args = [since]
    if user_id:
        q += " AND user_id = ?"
        args.append(user_id)
    rows = db_query(q, args)
    by_day, by_type, by_crit, by_verdict = {}, {}, {}, {}
    canary_hits = 0
    for r in rows:
        day = datetime.fromtimestamp(r["ts"], tz=timezone.utc)\
            .strftime("%Y-%m-%d")
        by_day.setdefault(day, {"BLOCK": 0, "FLAG": 0})
        if r["verdict"] in by_day[day]:
            by_day[day][r["verdict"]] += 1
        by_type[r["attack_type"] or "unknown"] = \
            by_type.get(r["attack_type"] or "unknown", 0) + 1
        by_crit[r["criticality"] or "UNKNOWN"] = \
            by_crit.get(r["criticality"] or "UNKNOWN", 0) + 1
        by_verdict[r["verdict"]] = by_verdict.get(r["verdict"], 0) + 1
        canary_hits += int(r["canary"])
    by_day = dict(sorted(by_day.items()))
    return {
        "window_days": days,
        "total_events": len(rows),
        "by_verdict": by_verdict,
        "by_type": by_type,
        "by_criticality": by_crit,
        "by_day": by_day,
        "canary_hits": canary_hits,
    }


def flag_streak(session_id):
    """Consecutive recent FLAG/BLOCK verdicts for a session (newest first)."""
    if not session_id:
        return 0
    rows = db_query(
        "SELECT verdict FROM events WHERE session_id = ? AND source='input'"
        " ORDER BY ts DESC LIMIT 5", (session_id,))
    streak = 0
    for r in rows:
        if r["verdict"] in ("FLAG", "BLOCK"):
            streak += 1
        else:
            break
    return streak


def session_history(session_id, limit=20):
    rows = db_query(
        "SELECT ts, verdict, probability FROM events WHERE session_id = ?"
        " ORDER BY ts ASC LIMIT ?", (session_id or "anon", limit))
    return [{"verdict": r["verdict"], "probability": r["probability"]}
            for r in rows]


def count_all():
    return db_query("SELECT COUNT(*) AS c FROM events", one=True)["c"]


def period_range(period):
    now = datetime.now(timezone.utc)
    if period == "daily":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return start.timestamp(), "Daily", start
    if period == "weekly":
        start = (now - timedelta(days=now.weekday())).replace(
            hour=0, minute=0, second=0, microsecond=0)
        return start.timestamp(), "Weekly", start
    start = (now.replace(day=1, hour=0, minute=0, second=0, microsecond=0))
    return start.timestamp(), "Monthly", start
